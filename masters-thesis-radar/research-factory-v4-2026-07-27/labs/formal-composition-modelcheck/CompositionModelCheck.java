import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Dependency-free finite model check for the manuscript's composition claims.
 *
 * This program imports no Python result, adapter, oracle, or expected-label
 * module. It exhausts the finite state spaces declared below and writes one
 * deterministic JSON result.
 */
public final class CompositionModelCheck {
    private record BindingProfile(String name, int protectedMask) {}
    private record ScheduleResult(String schedule, boolean oracle,
                                  boolean atomic, boolean singleRead) {}

    private static final int EFFECT = 1;
    private static final int RESOURCE = 2;
    private static final int TIME = 4;
    private static final int PROFILE = 8;

    private static final List<BindingProfile> BINDING_PROFILES = List.of(
        new BindingProfile("boolean_only", 0),
        new BindingProfile("effect_resource", EFFECT | RESOURCE),
        new BindingProfile("effect_resource_profile",
                           EFFECT | RESOURCE | PROFILE),
        new BindingProfile("effect_resource_time",
                           EFFECT | RESOURCE | TIME),
        new BindingProfile("full_effect_resource_time_profile",
                           EFFECT | RESOURCE | TIME | PROFILE)
    );

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String booleanIndistinguishabilityJson() {
        int composerCases = 0;
        int unavoidableErrorCases = 0;
        for (boolean allOnesOutput : List.of(false, true)) {
            composerCases++;
            boolean matchedExpected = true;
            boolean mismatchExpected = false;
            boolean matchedError = allOnesOutput != matchedExpected;
            boolean mismatchError = allOnesOutput != mismatchExpected;
            require(matchedError ^ mismatchError,
                    "exactly one all-ones witness must be misclassified");
            unavoidableErrorCases++;
        }
        require(composerCases == 2 && unavoidableErrorCases == 2,
                "proof-by-cases over f(11111) incomplete");
        return """
          "boolean_indistinguishability": {
            "local_vector": [1, 1, 1, 1, 1],
            "composer_output_cases": 2,
            "cases_with_unavoidable_error": 2,
            "minimum_errors_across_matched_mismatch_pair": 1,
            "passed": true
          }""";
    }

    private static String bindingRefinementJson() {
        Map<String, Integer> falseAllows = new LinkedHashMap<>();
        Map<String, List<Integer>> admitted = new LinkedHashMap<>();
        for (BindingProfile profile : BINDING_PROFILES) {
            List<Integer> states = new ArrayList<>();
            for (int agreementMask = 0; agreementMask < 16; agreementMask++) {
                boolean allow = (agreementMask & profile.protectedMask())
                                == profile.protectedMask();
                if (allow) {
                    states.add(agreementMask);
                }
            }
            admitted.put(profile.name(), states);
            int mismatches = (int) states.stream().filter(mask -> mask != 15).count();
            falseAllows.put(profile.name(), mismatches);
        }

        require(falseAllows.get("boolean_only") == 15,
                "Boolean-only mismatch count");
        require(falseAllows.get("effect_resource") == 3,
                "effect/resource mismatch count");
        require(falseAllows.get("effect_resource_profile") == 1,
                "profile-protected mismatch count");
        require(falseAllows.get("effect_resource_time") == 1,
                "time-protected mismatch count");
        require(falseAllows.get("full_effect_resource_time_profile") == 0,
                "full binding must reject every mismatch");

        List<Integer> er = admitted.get("effect_resource");
        List<Integer> erp = admitted.get("effect_resource_profile");
        List<Integer> ert = admitted.get("effect_resource_time");
        List<Integer> full = admitted.get("full_effect_resource_time_profile");
        require(er.containsAll(erp) && er.containsAll(ert),
                "partial refinements must be subsets of effect/resource");
        require(erp.containsAll(full) && ert.containsAll(full),
                "full schema must refine both three-coordinate schemas");
        require(er.size() > erp.size() && er.size() > ert.size()
                && erp.size() > full.size() && ert.size() > full.size(),
                "refinements must be strict");

        StringBuilder counts = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, Integer> entry : falseAllows.entrySet()) {
            if (!first) counts.append(",\n");
            counts.append("        ").append(quote(entry.getKey()))
                  .append(": ").append(entry.getValue());
            first = false;
        }
        return """
          "binding_refinement": {
            "coordinates": ["effect", "resource", "time", "profile"],
            "agreement_states_exhausted": 16,
            "false_allows_over_all_15_mismatch_states": {
        """ + counts + """

            },
            "strict_subset_relations_checked": 4,
            "passed": true
          }""";
    }

    private static void permutations(List<String> values, int index,
                                     List<List<String>> output) {
        if (index == values.size()) {
            output.add(List.copyOf(values));
            return;
        }
        for (int i = index; i < values.size(); i++) {
            String tmp = values.get(index);
            values.set(index, values.get(i));
            values.set(i, tmp);
            permutations(values, index + 1, output);
            tmp = values.get(index);
            values.set(index, values.get(i));
            values.set(i, tmp);
        }
    }

    private static String revocationJson() {
        List<List<String>> schedules = new ArrayList<>();
        permutations(new ArrayList<>(Arrays.asList("R", "X", "C")), 0, schedules);
        int atomicMismatches = 0;
        int singleReadFalseAllows = 0;
        List<String> counterexamples = new ArrayList<>();
        for (List<String> order : schedules) {
            int r = order.indexOf("R");
            int x = order.indexOf("X");
            int c = order.indexOf("C");
            boolean oracle = c < x;
            boolean atomic = c < x;
            boolean activeAtRead = r < x;
            boolean singleRead = activeAtRead;
            if (atomic != oracle) atomicMismatches++;
            if (singleRead && !oracle) {
                singleReadFalseAllows++;
                counterexamples.add(String.join("<", order));
            }
        }
        require(schedules.size() == 6, "three-event schedule count");
        require(atomicMismatches == 0, "atomic guard must match commit oracle");
        require(singleReadFalseAllows > 0,
                "single-read profile must expose a TOCTOU counterexample");
        require(counterexamples.contains("R<X<C"),
                "canonical read-revoke-commit counterexample absent");

        List<List<String>> doubleSchedules = new ArrayList<>();
        permutations(new ArrayList<>(Arrays.asList("R1", "R2", "X", "C")),
                     0, doubleSchedules);
        int validDoubleSchedules = 0;
        int doubleReadFalseAllows = 0;
        boolean canonicalDoubleFound = false;
        for (List<String> order : doubleSchedules) {
            int r1 = order.indexOf("R1");
            int r2 = order.indexOf("R2");
            int x = order.indexOf("X");
            int c = order.indexOf("C");
            if (!(r1 < r2 && r2 < c)) continue;
            validDoubleSchedules++;
            boolean oracle = c < x;
            boolean secondReadActive = r2 < x;
            boolean doubleRead = secondReadActive;
            if (doubleRead && !oracle) {
                doubleReadFalseAllows++;
                if (order.equals(List.of("R1", "R2", "X", "C"))) {
                    canonicalDoubleFound = true;
                }
            }
        }
        require(validDoubleSchedules == 4,
                "topologically valid double-read schedules");
        require(doubleReadFalseAllows > 0 && canonicalDoubleFound,
                "double-read final-read/commit gap absent");

        return """
          "revocation_model": {
            "three_event_schedules_exhausted": 6,
            "atomic_guard_oracle_mismatches": %d,
            "single_read_false_allow_schedules": %d,
            "single_read_counterexamples": %s,
            "double_read_topological_schedules": %d,
            "double_read_false_allow_schedules": %d,
            "canonical_double_read_counterexample": "R1<R2<X<C",
            "passed": true
          }""".formatted(
              atomicMismatches,
              singleReadFalseAllows,
              "[" + counterexamples.stream().map(CompositionModelCheck::quote)
                                   .reduce((a, b) -> a + ", " + b).orElse("") + "]",
              validDoubleSchedules,
              doubleReadFalseAllows
          );
    }

    public static void main(String[] args) throws IOException {
        require(args.length == 1, "usage: CompositionModelCheck OUTPUT.json");
        String json = """
        {
          "lab": "formal-composition-modelcheck",
          "implementation": "standalone Java finite-state enumeration",
          "imports_author_oracle": false,
          "all_passed": true,
        %s,
        %s,
        %s,
          "claim_boundary": "Finite exhaustive check of the declared Boolean, four-coordinate binding, and bounded revocation models; not a proof of every deployed implementation."
        }
        """.formatted(
            booleanIndistinguishabilityJson(),
            bindingRefinementJson(),
            revocationJson()
        );
        Path output = Path.of(args[0]);
        Files.writeString(output, json, StandardCharsets.UTF_8);
        System.out.print(json);
    }
}
