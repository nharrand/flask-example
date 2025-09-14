# Python/Atheris base image recommended for CFLite Python projects
FROM gcr.io/oss-fuzz-base/base-builder-python

# Project files
WORKDIR /src
COPY . /src

# Install runtime deps for the project (Flask only here)
RUN pip3 install -r requirements.txt

# No native extensions here, so nothing else needed.
