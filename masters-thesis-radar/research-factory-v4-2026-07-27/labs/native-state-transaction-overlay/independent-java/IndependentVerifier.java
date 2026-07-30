import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Independent compiled appraisal path for the native-state transaction overlay.
 *
 * This program deliberately uses no code from native_state_adapter.py.  It
 * implements its own JSON parser, transcript/PCR derivations, policy appraisal,
 * mutation generator, and output serializer.  The only native verification
 * dependency is the tpm2_checkquote executable.
 */
public final class IndependentVerifier {
    private static final String DOMAIN = "tyche.state.qual.v1";
    private static final int PCR_INDEX = 16;
    private static final List<String> MUTATIONS = List.of(
        "quote_message_flip",
        "signature_flip",
        "pcr_blob_flip",
        "challenge_replay",
        "transaction_substitution",
        "corpus_hash_substitution",
        "measurement_substitution",
        "window_substitution"
    );
    private static final Pattern MEASUREMENT =
        Pattern.compile("^sha256:([0-9a-f]{64})$");
    private static final Pattern PCR_LINE =
        Pattern.compile("(?im)^\\s*16:\\s*0x([0-9a-f]{64})\\s*$");

    private record NativeRun(int rc, String stdout, String stderr) {}

    private record Appraisal(
        String result,
        String gate,
        int nativeRc,
        boolean pcrMatch,
        List<String> failures,
        String qualifyingData,
        String qualifyingDataPreimage,
        String nativeStdoutSha256,
        String nativeStderrSha256,
        boolean rootAkPinMatch
    ) {
        Map<String, Object> asJson() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("result", result);
            out.put("gate", gate);
            out.put("native_rc", nativeRc);
            out.put("pcr_match", pcrMatch);
            out.put("root_ak_pin_match", rootAkPinMatch);
            out.put("failures", new ArrayList<>(failures));
            out.put("qualifying_data", qualifyingData);
            out.put("qualifying_data_preimage", qualifyingDataPreimage);
            out.put("native_stdout_sha256", nativeStdoutSha256);
            out.put("native_stderr_sha256", nativeStderrSha256);
            return out;
        }
    }

    private record PrimaryResult(String result, String gate) {}

    private static final class Configuration {
        Path overlay;
        Path policy;
        Path primaryVerdicts;
        Path primaryMutations;
        Path output;

        static Configuration parse(String[] args) {
            Configuration c = new Configuration();
            for (int i = 0; i < args.length; i += 2) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("missing value for " + args[i]);
                }
                Path value = Path.of(args[i + 1]);
                switch (args[i]) {
                    case "--overlay" -> c.overlay = value;
                    case "--policy" -> c.policy = value;
                    case "--primary-verdicts" -> c.primaryVerdicts = value;
                    case "--primary-mutations" -> c.primaryMutations = value;
                    case "--output" -> c.output = value;
                    default -> throw new IllegalArgumentException(
                        "unknown argument: " + args[i]
                    );
                }
            }
            if (c.overlay == null || c.policy == null
                || c.primaryVerdicts == null || c.primaryMutations == null
                || c.output == null) {
                throw new IllegalArgumentException("all five path arguments are required");
            }
            return c;
        }
    }

    public static void main(String[] args) throws Exception {
        long started = System.nanoTime();
        Configuration cfg = Configuration.parse(args);
        Files.createDirectories(cfg.output);

        String overlayRaw = Files.readString(cfg.overlay, StandardCharsets.UTF_8);
        String policyRaw = Files.readString(cfg.policy, StandardCharsets.UTF_8);
        Map<String, Object> overlay = object(Json.parse(overlayRaw));
        Map<String, Object> policy = object(Json.parse(policyRaw));

        if (!DOMAIN.equals(string(policy.get("profile")))) {
            throw new IllegalStateException("unexpected policy profile");
        }
        if (countKey(overlay, "status") != 0 || countKey(policy, "status") != 0) {
            throw new IllegalStateException(
                "independent inputs unexpectedly contain a source status key"
            );
        }

        Map<String, Map<String, Object>> roots = indexRoots(array(overlay.get("roots")));
        List<Map<String, Object>> vectors = new ArrayList<>();
        for (Object item : array(overlay.get("vectors"))) {
            vectors.add(object(item));
        }
        vectors.sort(Comparator.comparing(
            value -> transactionId(value)
        ));

        Map<String, PrimaryResult> primaryBaseline =
            readPrimaryBaseline(cfg.primaryVerdicts);
        Map<String, PrimaryResult> primaryMutations =
            readPrimaryMutations(cfg.primaryMutations);
        boolean topLevelBindings =
            DOMAIN.equals(nullableString(overlay.get("profile")))
            && nullableString(overlay.get("source_corpus_sha256")).equals(
                nullableString(policy.get("source_corpus_sha256"))
            );

        List<Map<String, Object>> baselineRows = new ArrayList<>();
        Map<String, Appraisal> independentById = new HashMap<>();
        Map<String, Integer> classCounts = new TreeMap<>();
        Map<String, Integer> rootUseCounts = new TreeMap<>();
        int baselineOracleMatches = 0;
        int baselinePrimaryParity = 0;
        int rootPinMatches = 0;
        Set<String> transactionIds = new HashSet<>();
        Set<String> challengeValues = new HashSet<>();
        Set<String> quoteHashes = new HashSet<>();
        Set<String> akHashes = new HashSet<>();

        for (Map<String, Object> evidence : vectors) {
            String transactionId = transactionId(evidence);
            rootUseCounts.merge(string(evidence.get("root_id")), 1, Integer::sum);
            if (!transactionIds.add(transactionId)) {
                throw new IllegalStateException(
                    "duplicate transaction id: " + transactionId
                );
            }
            Map<String, Object> envelope = object(evidence.get("envelope"));
            challengeValues.add(string(envelope.get("challenge")));
            quoteHashes.add(sha256Hex(
                decodeBase64(string(evidence.get("quote_msg_b64")))
            ));
            akHashes.add(sha256Hex(
                decodeBase64(string(evidence.get("ak_pub_b64")))
            ));

            Appraisal result = appraise(evidence, policy, roots);
            independentById.put(transactionId, result);
            classCounts.merge(result.result(), 1, Integer::sum);
            if (result.rootAkPinMatch()) {
                rootPinMatches++;
            }
            String expected = string(evidence.get("expected_state_class"));
            boolean oracleMatch = result.result().equals(expected);
            if (oracleMatch) {
                baselineOracleMatches++;
            }
            PrimaryResult primary = primaryBaseline.get(transactionId);
            boolean primaryParity = primary != null
                && result.result().equals(primary.result())
                && result.gate().equals(primary.gate());
            if (primaryParity) {
                baselinePrimaryParity++;
            }

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("transaction_id", transactionId);
            row.put("root_id", string(evidence.get("root_id")));
            row.put("ak_algorithm", string(evidence.get("ak_algorithm")));
            row.put("expected_state_class", expected);
            row.put("observed_state_class", result.result());
            row.put("observed_gate", result.gate());
            row.put("oracle_match", oracleMatch);
            row.put("primary_state_class", primary == null ? null : primary.result());
            row.put("primary_gate", primary == null ? null : primary.gate());
            row.put("primary_parity", primaryParity);
            row.put("appraisal", result.asJson());
            baselineRows.add(row);
        }
        writeJsonl(cfg.output.resolve("verdicts.jsonl"), baselineRows);

        Map<String, Map<String, Object>> representatives = new TreeMap<>();
        for (Map<String, Object> evidence : vectors) {
            representatives.putIfAbsent(string(evidence.get("root_id")), evidence);
        }

        List<Map<String, Object>> mutationRows = new ArrayList<>();
        int mutationRejections = 0;
        int mutationPrimaryParity = 0;
        int rootOffset = 0;
        for (Map.Entry<String, Map<String, Object>> entry
                : representatives.entrySet()) {
            Map<String, Object> evidence = entry.getValue();
            Map<String, Object> alternate =
                vectors.get((rootOffset + 37) % vectors.size());
            if (transactionId(alternate).equals(transactionId(evidence))) {
                alternate = vectors.get((rootOffset + 38) % vectors.size());
            }
            for (String mutation : MUTATIONS) {
                Map<String, Object> candidate =
                    mutateEvidence(evidence, mutation, alternate);
                Appraisal result = appraise(candidate, policy, roots);
                boolean rejected =
                    result.result().equals("CRYPTOGRAPHIC_FAILURE");
                if (rejected) {
                    mutationRejections++;
                }
                String key = mutationKey(
                    entry.getKey(), transactionId(evidence), mutation
                );
                PrimaryResult primary = primaryMutations.get(key);
                boolean primaryParity = primary != null
                    && result.result().equals(primary.result())
                    && result.gate().equals(primary.gate());
                if (primaryParity) {
                    mutationPrimaryParity++;
                }

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("root_id", entry.getKey());
                row.put("source_transaction_id", transactionId(evidence));
                row.put("mutation", mutation);
                row.put("expected_state_class", "CRYPTOGRAPHIC_FAILURE");
                row.put("observed_state_class", result.result());
                row.put("observed_gate", result.gate());
                row.put("rejected_as_expected", rejected);
                row.put("primary_state_class",
                    primary == null ? null : primary.result());
                row.put("primary_gate", primary == null ? null : primary.gate());
                row.put("primary_parity", primaryParity);
                row.put("appraisal", result.asJson());
                mutationRows.add(row);
            }
            rootOffset++;
        }
        writeJsonl(cfg.output.resolve("mutation-verdicts.jsonl"), mutationRows);

        int expectedBaseline = 104;
        int expectedMutations = 64;
        boolean balancedRoots = roots.entrySet().stream().allMatch(entry ->
            integer(entry.getValue().get("transactions")) == 13
                && rootUseCounts.getOrDefault(entry.getKey(), 0) == 13
        );
        boolean primaryCoverage =
            primaryBaseline.size() == expectedBaseline
                && primaryMutations.size() == expectedMutations;
        boolean invariantsPassed =
            topLevelBindings
            && primaryCoverage
            && vectors.size() == expectedBaseline
            && roots.size() == 8
            && balancedRoots
            && transactionIds.size() == expectedBaseline
            && challengeValues.size() == expectedBaseline
            && quoteHashes.size() == expectedBaseline
            && akHashes.size() == 8
            && rootPinMatches == expectedBaseline;
        Map<String, Object> assertions = new LinkedHashMap<>();
        assertions.put("compiled_java_path", true);
        assertions.put("python_adapter_not_imported", true);
        assertions.put("structural_source_corpus_not_read", true);
        assertions.put("source_status_key_absent", true);
        assertions.put("top_level_profile_and_corpus_bound", topLevelBindings);
        assertions.put("baseline_count_104", vectors.size() == expectedBaseline);
        assertions.put("eight_roots", roots.size() == 8);
        assertions.put("thirteen_vectors_per_root", balancedRoots);
        assertions.put("eight_distinct_ak_public_keys", akHashes.size() == 8);
        assertions.put("all_ak_keys_match_root_pins",
            rootPinMatches == expectedBaseline);
        assertions.put("all_transaction_ids_unique",
            transactionIds.size() == expectedBaseline);
        assertions.put("all_challenges_unique",
            challengeValues.size() == expectedBaseline);
        assertions.put("all_quote_messages_unique",
            quoteHashes.size() == expectedBaseline);
        assertions.put("primary_comparison_has_complete_coverage",
            primaryCoverage);
        assertions.put("baseline_oracle_match_104",
            baselineOracleMatches == expectedBaseline);
        assertions.put("baseline_primary_state_and_gate_parity_104",
            baselinePrimaryParity == expectedBaseline);
        assertions.put("mutation_count_64",
            mutationRows.size() == expectedMutations);
        assertions.put("all_mutations_rejected",
            mutationRejections == expectedMutations);
        assertions.put("mutation_primary_state_and_gate_parity_64",
            mutationPrimaryParity == expectedMutations);
        int assertionsPassed = (int) assertions.values().stream()
            .filter(Boolean.TRUE::equals)
            .count();
        boolean allPassed = assertionsPassed == assertions.size();
        Files.writeString(
            cfg.output.resolve("assertions.json"),
            Json.stringify(assertions) + "\n",
            StandardCharsets.UTF_8
        );

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("lab", "native-state-independent-compiled-verifier");
        summary.put(
            "implementation",
            "OpenJDK compiled Java; own JSON/transcript/PCR/policy/mutation "
                + "implementation; tpm2_checkquote subprocess"
        );
        summary.put("imports_python_adapter", false);
        summary.put("reads_structural_source_corpus", false);
        summary.put("source_status_fields_read", 0);
        summary.put("top_level_profile_and_corpus_bindings", topLevelBindings);
        summary.put("baseline_cases", vectors.size());
        summary.put("baseline_oracle_matches", baselineOracleMatches);
        summary.put("baseline_primary_state_and_gate_parity",
            baselinePrimaryParity);
        summary.put("baseline_state_class_counts", classCounts);
        summary.put("mutation_cases", mutationRows.size());
        summary.put("mutation_rejections", mutationRejections);
        summary.put("mutation_primary_state_and_gate_parity",
            mutationPrimaryParity);
        summary.put("primary_comparison_coverage", primaryCoverage);
        summary.put("roots", roots.size());
        summary.put("balanced_13_vectors_per_root", balancedRoots);
        summary.put("distinct_ak_public_keys", akHashes.size());
        summary.put("root_ak_pin_matches", rootPinMatches);
        summary.put("distinct_transaction_ids", transactionIds.size());
        summary.put("distinct_challenges", challengeValues.size());
        summary.put("distinct_quote_messages", quoteHashes.size());
        summary.put("invariants_passed", invariantsPassed);
        summary.put("assertions", assertions.size());
        summary.put("assertions_passed", assertionsPassed);
        summary.put("all_passed", allPassed);
        summary.put(
            "claim_boundary",
            "independent implementation agreement over author-designed "
                + "software-TPM evidence on one x86_64 host; not external "
                + "ground truth, hardware-rooted identity, trusted time, "
                + "remote-runtime evidence, or independent-host replication"
        );
        Files.writeString(
            cfg.output.resolve("summary.json"),
            Json.stringify(summary) + "\n",
            StandardCharsets.UTF_8
        );

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("java_runtime", System.getProperty("java.runtime.version"));
        metadata.put("java_vm", System.getProperty("java.vm.name"));
        metadata.put("os_name", System.getProperty("os.name"));
        metadata.put("os_arch", System.getProperty("os.arch"));
        metadata.put("tpm2_checkquote_version", toolVersion());
        metadata.put("overlay_sha256", sha256Hex(Files.readAllBytes(cfg.overlay)));
        metadata.put("policy_sha256", sha256Hex(Files.readAllBytes(cfg.policy)));
        metadata.put("primary_verdicts_sha256",
            sha256Hex(Files.readAllBytes(cfg.primaryVerdicts)));
        metadata.put("primary_mutations_sha256",
            sha256Hex(Files.readAllBytes(cfg.primaryMutations)));
        metadata.put("elapsed_seconds",
            Math.round((System.nanoTime() - started) / 1_000.0) / 1_000_000.0);
        Files.writeString(
            cfg.output.resolve("run-metadata.json"),
            Json.stringify(metadata) + "\n",
            StandardCharsets.UTF_8
        );

        System.out.println(Json.stringify(summary));
        if (!allPassed) {
            System.exit(1);
        }
    }

    private static Appraisal appraise(
        Map<String, Object> evidence,
        Map<String, Object> policy,
        Map<String, Map<String, Object>> roots
    ) throws Exception {
        Map<String, Object> envelope = object(evidence.get("envelope"));
        String transactionId = nullableString(envelope.get("transaction_id"));
        List<String> failures = new ArrayList<>();

        if (!DOMAIN.equals(nullableString(envelope.get("profile")))) {
            failures.add("profile_binding");
        }
        if (integer(envelope.get("pcr_index")) != PCR_INDEX) {
            failures.add("pcr_index_binding");
        }
        if (!nullableString(envelope.get("source_corpus_sha256")).equals(
                nullableString(policy.get("source_corpus_sha256")))) {
            failures.add("source_corpus_binding");
        }

        Map<String, Object> expectedChallenges =
            object(policy.get("expected_challenges"));
        if (!nullableString(expectedChallenges.get(transactionId)).equals(
                nullableString(envelope.get("challenge")))) {
            failures.add("challenge_binding");
        }
        Map<String, Object> capsuleIds = object(policy.get("capsule_ids"));
        if (!nullableString(capsuleIds.get(transactionId)).equals(
                nullableString(envelope.get("capsule_id")))) {
            failures.add("transaction_subject_binding");
        }

        String rootId = nullableString(evidence.get("root_id"));
        Map<String, Object> root = roots.get(rootId);
        byte[] akPub = decodeBase64(nullableString(evidence.get("ak_pub_b64")));
        boolean rootAkPinMatch = root != null
            && sha256Hex(akPub).equals(nullableString(root.get("ak_pub_sha256")));
        if (!rootAkPinMatch) {
            failures.add("root_ak_binding");
        }
        if (root == null || !nullableString(root.get("algorithm")).equals(
                nullableString(evidence.get("ak_algorithm")))) {
            failures.add("root_algorithm_binding");
        }

        String preimage = transcript(envelope);
        String qualifying = sha256Hex(preimage.getBytes(StandardCharsets.UTF_8));
        String qOption = hex(qualifying.getBytes(StandardCharsets.US_ASCII));
        String expectedPcr = "";
        try {
            expectedPcr = expectedPcr(
                nullableString(envelope.get("observed_measurement"))
            );
        } catch (IllegalArgumentException error) {
            failures.add("malformed_measurement");
        }

        NativeRun nativeRun;
        boolean pcrMatch = false;
        try {
            byte[] quoteMsg =
                decodeBase64(nullableString(evidence.get("quote_msg_b64")));
            byte[] quoteSig =
                decodeBase64(nullableString(evidence.get("quote_sig_b64")));
            byte[] pcrBin =
                decodeBase64(nullableString(evidence.get("pcr_bin_b64")));
            nativeRun = runCheckquote(
                akPub, quoteMsg, quoteSig, pcrBin, qOption
            );
            Matcher matcher = PCR_LINE.matcher(nativeRun.stdout());
            while (matcher.find()) {
                if (matcher.group(1).equalsIgnoreCase(expectedPcr)) {
                    pcrMatch = true;
                }
            }
            if (nativeRun.rc() != 0) {
                failures.add("native_quote");
            }
            if (!pcrMatch) {
                failures.add("pcr_measurement_binding");
            }
        } catch (Exception error) {
            nativeRun = new NativeRun(
                -1, "", error.getClass().getSimpleName() + ":" + error.getMessage()
            );
            failures.add("malformed_native_evidence:"
                + error.getClass().getSimpleName());
        }

        String result;
        String gate;
        String observed = nullableString(envelope.get("observed_measurement"));
        if (!failures.isEmpty()) {
            result = "CRYPTOGRAPHIC_FAILURE";
            gate = "state.native_evidence";
        } else if (stringSet(array(policy.get("denied_measurements")))
                .contains(observed)) {
            result = "CONTRAINDICATED";
            gate = "state.contraindicated";
        } else if (!withinWindow(
                nullableString(envelope.get("issued_at")),
                nullableString(policy.get("decision_time")),
                nullableString(envelope.get("expires_at")))) {
            result = "STALE";
            gate = "state.stale";
        } else {
            Map<String, Object> references =
                object(policy.get("reference_measurements"));
            if (!observed.equals(nullableString(references.get(transactionId)))) {
                result = "REFERENCE_MISMATCH";
                gate = "state.reference";
            } else {
                result = "PASS";
                gate = "state.verified";
            }
        }

        return new Appraisal(
            result,
            gate,
            nativeRun.rc(),
            pcrMatch,
            List.copyOf(failures),
            qualifying,
            preimage,
            sha256Hex(nativeRun.stdout().getBytes(StandardCharsets.UTF_8)),
            sha256Hex(nativeRun.stderr().getBytes(StandardCharsets.UTF_8)),
            rootAkPinMatch
        );
    }

    private static NativeRun runCheckquote(
        byte[] akPub,
        byte[] quoteMsg,
        byte[] quoteSig,
        byte[] pcrBin,
        String qOption
    ) throws Exception {
        Path directory = Files.createTempDirectory("tyche-independent-check-");
        try {
            Path ak = directory.resolve("ak.pub");
            Path msg = directory.resolve("quote.msg");
            Path sig = directory.resolve("quote.sig");
            Path pcr = directory.resolve("pcr.bin");
            Path stdout = directory.resolve("stdout.txt");
            Path stderr = directory.resolve("stderr.txt");
            Files.write(ak, akPub);
            Files.write(msg, quoteMsg);
            Files.write(sig, quoteSig);
            Files.write(pcr, pcrBin);
            Process process = new ProcessBuilder(
                "tpm2_checkquote",
                "-u", ak.toString(),
                "-m", msg.toString(),
                "-s", sig.toString(),
                "-q", qOption,
                "-g", "sha256",
                "-f", pcr.toString()
            )
                .redirectOutput(stdout.toFile())
                .redirectError(stderr.toFile())
                .start();
            int rc = process.waitFor();
            return new NativeRun(
                rc,
                Files.readString(stdout, StandardCharsets.UTF_8),
                Files.readString(stderr, StandardCharsets.UTF_8)
            );
        } finally {
            deleteTree(directory);
        }
    }

    private static Map<String, Object> mutateEvidence(
        Map<String, Object> source,
        String mutation,
        Map<String, Object> alternate
    ) {
        Map<String, Object> candidate = object(deepCopy(source));
        Map<String, Object> envelope = object(candidate.get("envelope"));
        Map<String, Object> alternateEnvelope = object(alternate.get("envelope"));
        switch (mutation) {
            case "quote_message_flip" ->
                candidate.put("quote_msg_b64",
                    flipBase64(string(candidate.get("quote_msg_b64"))));
            case "signature_flip" ->
                candidate.put("quote_sig_b64",
                    flipBase64(string(candidate.get("quote_sig_b64"))));
            case "pcr_blob_flip" -> {
                byte[] raw = decodeBase64(string(candidate.get("pcr_bin_b64")));
                byte[] needle = unhex(expectedPcr(
                    string(envelope.get("observed_measurement"))
                ));
                int offset = indexOf(raw, needle);
                if (offset < 0) {
                    throw new IllegalStateException(
                        "quoted PCR value not found in PCR blob"
                    );
                }
                raw[offset] ^= 0x01;
                candidate.put("pcr_bin_b64",
                    Base64.getEncoder().encodeToString(raw));
            }
            case "challenge_replay" ->
                envelope.put("challenge", alternateEnvelope.get("challenge"));
            case "transaction_substitution" ->
                envelope.put("transaction_id",
                    alternateEnvelope.get("transaction_id"));
            case "corpus_hash_substitution" ->
                envelope.put("source_corpus_sha256", "0".repeat(64));
            case "measurement_substitution" ->
                envelope.put("observed_measurement",
                    alternateEnvelope.get("observed_measurement"));
            case "window_substitution" ->
                envelope.put("expires_at", "2099-01-01T00:00:00Z");
            default -> throw new IllegalArgumentException(
                "unknown mutation: " + mutation
            );
        }
        return candidate;
    }

    private static Map<String, Map<String, Object>> indexRoots(List<Object> values) {
        Map<String, Map<String, Object>> out = new TreeMap<>();
        for (Object value : values) {
            Map<String, Object> root = object(value);
            String id = string(root.get("root_id"));
            if (out.put(id, root) != null) {
                throw new IllegalStateException("duplicate root id: " + id);
            }
        }
        return out;
    }

    private static Map<String, PrimaryResult> readPrimaryBaseline(Path path)
            throws IOException {
        Map<String, PrimaryResult> out = new HashMap<>();
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            if (line.isBlank()) {
                continue;
            }
            Map<String, Object> row = object(Json.parse(line));
            Map<String, Object> appraisal = object(row.get("appraisal"));
            out.put(
                string(row.get("transaction_id")),
                new PrimaryResult(
                    string(row.get("observed_state_class")),
                    string(appraisal.get("gate"))
                )
            );
        }
        return out;
    }

    private static Map<String, PrimaryResult> readPrimaryMutations(Path path)
            throws IOException {
        Map<String, PrimaryResult> out = new HashMap<>();
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            if (line.isBlank()) {
                continue;
            }
            Map<String, Object> row = object(Json.parse(line));
            Map<String, Object> appraisal = object(row.get("appraisal"));
            String key = mutationKey(
                string(row.get("root_id")),
                string(row.get("source_transaction_id")),
                string(row.get("mutation"))
            );
            out.put(
                key,
                new PrimaryResult(
                    string(row.get("observed_state_class")),
                    string(appraisal.get("gate"))
                )
            );
        }
        return out;
    }

    private static String mutationKey(
        String root, String transaction, String mutation
    ) {
        return root + "\u001f" + transaction + "\u001f" + mutation;
    }

    private static String transactionId(Map<String, Object> evidence) {
        return string(object(evidence.get("envelope")).get("transaction_id"));
    }

    private static String transcript(Map<String, Object> envelope) {
        return DOMAIN
            + "|corpus=" + string(envelope.get("source_corpus_sha256"))
            + "|transaction=" + string(envelope.get("transaction_id"))
            + "|capsule=" + string(envelope.get("capsule_id"))
            + "|measurement=" + string(envelope.get("observed_measurement"))
            + "|issued=" + string(envelope.get("issued_at"))
            + "|expires=" + string(envelope.get("expires_at"))
            + "|challenge=" + string(envelope.get("challenge"));
    }

    private static String expectedPcr(String measurement) {
        Matcher matcher = MEASUREMENT.matcher(measurement);
        if (!matcher.matches()) {
            throw new IllegalArgumentException(
                "measurement is not sha256 lowercase hexadecimal"
            );
        }
        byte[] preimage = new byte[64];
        byte[] digest = unhex(matcher.group(1));
        System.arraycopy(digest, 0, preimage, 32, digest.length);
        return sha256Hex(preimage);
    }

    private static boolean withinWindow(
        String issued, String decision, String expires
    ) {
        try {
            Instant start = Instant.parse(issued);
            Instant point = Instant.parse(decision);
            Instant end = Instant.parse(expires);
            return !point.isBefore(start) && !point.isAfter(end);
        } catch (RuntimeException error) {
            return false;
        }
    }

    private static String flipBase64(String value) {
        byte[] raw = decodeBase64(value);
        if (raw.length == 0) {
            throw new IllegalArgumentException("cannot flip empty base64 value");
        }
        raw[raw.length - 1] ^= 0x01;
        return Base64.getEncoder().encodeToString(raw);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static Set<String> stringSet(List<Object> values) {
        Set<String> out = new HashSet<>();
        for (Object value : values) {
            out.add(string(value));
        }
        return out;
    }

    private static String toolVersion() throws Exception {
        Process process = new ProcessBuilder("tpm2_checkquote", "--version")
            .redirectErrorStream(true)
            .start();
        String output = new String(
            process.getInputStream().readAllBytes(), StandardCharsets.UTF_8
        ).trim();
        int rc = process.waitFor();
        if (rc != 0) {
            throw new IllegalStateException(
                "tpm2_checkquote --version failed: " + output
            );
        }
        return output;
    }

    private static void writeJsonl(
        Path path, List<Map<String, Object>> rows
    ) throws IOException {
        StringBuilder output = new StringBuilder();
        for (Map<String, Object> row : rows) {
            output.append(Json.stringify(row)).append('\n');
        }
        Files.writeString(path, output.toString(), StandardCharsets.UTF_8);
    }

    private static int countKey(Object value, String wanted) {
        if (value instanceof Map<?, ?> map) {
            int total = 0;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (wanted.equals(entry.getKey())) {
                    total++;
                }
                total += countKey(entry.getValue(), wanted);
            }
            return total;
        }
        if (value instanceof List<?> list) {
            int total = 0;
            for (Object item : list) {
                total += countKey(item, wanted);
            }
            return total;
        }
        return 0;
    }

    private static Object deepCopy(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                out.put((String) entry.getKey(), deepCopy(entry.getValue()));
            }
            return out;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>();
            for (Object item : list) {
                out.add(deepCopy(item));
            }
            return out;
        }
        return value;
    }

    private static void deleteTree(Path directory) throws IOException {
        if (!Files.exists(directory)) {
            return;
        }
        try (var stream = Files.walk(directory)) {
            for (Path path : stream.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static String sha256Hex(byte[] value) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private static byte[] decodeBase64(String value) {
        return Base64.getDecoder().decode(value);
    }

    private static byte[] unhex(String value) {
        if ((value.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hexadecimal length");
        }
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid hexadecimal");
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

    private static String hex(byte[] value) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] out = new char[value.length * 2];
        for (int i = 0; i < value.length; i++) {
            int current = value[i] & 0xff;
            out[i * 2] = digits[current >>> 4];
            out[i * 2 + 1] = digits[current & 0x0f];
        }
        return new String(out);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        if (!(value instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("expected JSON object");
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> array(Object value) {
        if (!(value instanceof List<?>)) {
            throw new IllegalArgumentException("expected JSON array");
        }
        return (List<Object>) value;
    }

    private static String string(Object value) {
        if (!(value instanceof String text)) {
            throw new IllegalArgumentException("expected JSON string");
        }
        return text;
    }

    private static String nullableString(Object value) {
        return value instanceof String text ? text : "";
    }

    private static int integer(Object value) {
        if (value instanceof BigDecimal number) {
            return number.intValueExact();
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.MIN_VALUE;
    }

    /** Minimal strict JSON parser and serializer used by the compiled path. */
    private static final class Json {
        private final String source;
        private int offset;

        private Json(String source) {
            this.source = source;
        }

        static Object parse(String source) {
            Json parser = new Json(source);
            Object value = parser.value();
            parser.space();
            if (parser.offset != source.length()) {
                throw parser.error("trailing JSON data");
            }
            return value;
        }

        static String stringify(Object value) {
            StringBuilder out = new StringBuilder();
            write(value, out);
            return out.toString();
        }

        private Object value() {
            space();
            if (offset >= source.length()) {
                throw error("unexpected end of JSON");
            }
            return switch (source.charAt(offset)) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        private Map<String, Object> object() {
            expect('{');
            Map<String, Object> out = new LinkedHashMap<>();
            space();
            if (take('}')) {
                return out;
            }
            while (true) {
                space();
                String key = string();
                space();
                expect(':');
                if (out.put(key, value()) != null) {
                    throw error("duplicate JSON object key: " + key);
                }
                space();
                if (take('}')) {
                    return out;
                }
                expect(',');
            }
        }

        private List<Object> array() {
            expect('[');
            List<Object> out = new ArrayList<>();
            space();
            if (take(']')) {
                return out;
            }
            while (true) {
                out.add(value());
                space();
                if (take(']')) {
                    return out;
                }
                expect(',');
            }
        }

        private String string() {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (offset < source.length()) {
                char current = source.charAt(offset++);
                if (current == '"') {
                    return out.toString();
                }
                if (current == '\\') {
                    if (offset >= source.length()) {
                        throw error("unterminated JSON escape");
                    }
                    char escaped = source.charAt(offset++);
                    switch (escaped) {
                        case '"' -> out.append('"');
                        case '\\' -> out.append('\\');
                        case '/' -> out.append('/');
                        case 'b' -> out.append('\b');
                        case 'f' -> out.append('\f');
                        case 'n' -> out.append('\n');
                        case 'r' -> out.append('\r');
                        case 't' -> out.append('\t');
                        case 'u' -> out.append(unicode());
                        default -> throw error("invalid JSON escape");
                    }
                } else {
                    if (current < 0x20) {
                        throw error("control character in JSON string");
                    }
                    out.append(current);
                }
            }
            throw error("unterminated JSON string");
        }

        private char unicode() {
            if (offset + 4 > source.length()) {
                throw error("short unicode escape");
            }
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit(source.charAt(offset++), 16);
                if (digit < 0) {
                    throw error("invalid unicode escape");
                }
                value = (value << 4) | digit;
            }
            return (char) value;
        }

        private Object literal(String text, Object value) {
            if (!source.startsWith(text, offset)) {
                throw error("invalid JSON literal");
            }
            offset += text.length();
            return value;
        }

        private BigDecimal number() {
            int start = offset;
            if (take('-')) {
                // sign consumed
            }
            if (take('0')) {
                // single leading zero
            } else {
                digits();
            }
            if (take('.')) {
                digits();
            }
            if (take('e') || take('E')) {
                take('+');
                take('-');
                digits();
            }
            if (start == offset) {
                throw error("invalid JSON value");
            }
            try {
                return new BigDecimal(source.substring(start, offset));
            } catch (NumberFormatException error) {
                throw error("invalid JSON number");
            }
        }

        private void digits() {
            int start = offset;
            while (offset < source.length()
                    && Character.isDigit(source.charAt(offset))) {
                offset++;
            }
            if (start == offset) {
                throw error("expected decimal digit");
            }
        }

        private void space() {
            while (offset < source.length()) {
                char current = source.charAt(offset);
                if (current == ' ' || current == '\n'
                        || current == '\r' || current == '\t') {
                    offset++;
                } else {
                    break;
                }
            }
        }

        private boolean take(char wanted) {
            if (offset < source.length() && source.charAt(offset) == wanted) {
                offset++;
                return true;
            }
            return false;
        }

        private void expect(char wanted) {
            if (!take(wanted)) {
                throw error("expected '" + wanted + "'");
            }
        }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException(
                message + " at character " + offset
            );
        }

        private static void write(Object value, StringBuilder out) {
            if (value == null) {
                out.append("null");
            } else if (value instanceof String text) {
                quote(text, out);
            } else if (value instanceof Boolean || value instanceof Number) {
                out.append(value);
            } else if (value instanceof Map<?, ?> map) {
                out.append('{');
                List<String> keys = new ArrayList<>();
                for (Object key : map.keySet()) {
                    keys.add((String) key);
                }
                Collections.sort(keys);
                boolean first = true;
                for (String key : keys) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    quote(key, out);
                    out.append(':');
                    write(map.get(key), out);
                }
                out.append('}');
            } else if (value instanceof List<?> list) {
                out.append('[');
                boolean first = true;
                for (Object item : list) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    write(item, out);
                }
                out.append(']');
            } else {
                throw new IllegalArgumentException(
                    "cannot serialize " + value.getClass()
                );
            }
        }

        private static void quote(String value, StringBuilder out) {
            out.append('"');
            for (int i = 0; i < value.length(); i++) {
                char current = value.charAt(i);
                switch (current) {
                    case '"' -> out.append("\\\"");
                    case '\\' -> out.append("\\\\");
                    case '\b' -> out.append("\\b");
                    case '\f' -> out.append("\\f");
                    case '\n' -> out.append("\\n");
                    case '\r' -> out.append("\\r");
                    case '\t' -> out.append("\\t");
                    default -> {
                        if (current < 0x20) {
                            out.append(String.format(Locale.ROOT, "\\u%04x",
                                (int) current));
                        } else {
                            out.append(current);
                        }
                    }
                }
            }
            out.append('"');
        }
    }
}
