# Isolated-container reproduction image for the V4 laboratory entry points.
#
# Review experiment E4 (cross-host closure) and review finding C-25: the
# `network_used: false` key in every run-metadata.json is an assertion written
# by the entry point about itself, not a measurement. This image exists so the
# assertion can be replaced by an enforced property: the build runs with
# --network=none against a local wheelhouse, and the run is executed with
# --network=none, so no network namespace is available to be used.
#
# Base image is pinned by digest, not by tag, so the tag cannot drift under
# the experiment. The digest below is the linux/amd64 python:3.12-slim image
# present in the local daemon store on 2026-07-27.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

# Interpreter and locale settings that remove avoidable sources of variation
# between the host run and the container run. PYTHONDONTWRITEBYTECODE mirrors
# the export already present in the laboratories' own run.sh.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PYTHONUNBUFFERED=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/repro

# The wheelhouse is staged into the build context by run-in-container.sh from
# the local pip HTTP cache. --no-index makes the absence of a network index a
# hard error rather than a silent fallback, so this layer cannot succeed by
# reaching outside the machine.
COPY wheelhouse/ /opt/repro/wheelhouse/
COPY requirements.txt /opt/repro/requirements.txt

RUN pip install --no-index --find-links=/opt/repro/wheelhouse \
        -r /opt/repro/requirements.txt \
 && python -c "import numpy, cryptography; \
assert numpy.__version__ == '2.5.0', numpy.__version__; \
assert cryptography.__version__ == '49.0.0', cryptography.__version__; \
print('pinned ok:', numpy.__version__, cryptography.__version__)"

COPY container-entry.sh /opt/repro/container-entry.sh
RUN chmod 0755 /opt/repro/container-entry.sh

ENTRYPOINT ["/opt/repro/container-entry.sh"]
