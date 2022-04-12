# FROM ubuntu:22.04
FROM ubuntu:18.04

# TODO remove sudo for user "libby" to avoid unwanted priv escalation from
# other attack vectors.

ARG libpp_root=./

RUN apt-get update && apt-get install -y sudo vim daemontools

ENV CC  /usr/bin/gcc
ENV CXX /usr/bin/g++
ENV LD /usr/bin/ld
ENV AR /usr/bin/ar
ENV AS /usr/bin/as
ENV NM /usr/bin/nm
ENV RANLIB /usr/bin/ranlib

ENV user  libby
ENV pass  ybbil
ENV group libby

ENV LIBPP_R 	/libfuzzpp
ENV OUT 	/libfuzzpp_out
ENV SHARED 	/libfuzzpp_shared

ARG USER_ID=1000
ARG GROUP_ID=1000
RUN mkdir -p /home && \
	groupadd -g ${GROUP_ID} ${group} && \
	useradd -l -u ${USER_ID} -K UMASK=0000 -d /home -g ${user} ${group} && \
	chown ${user}:${group} /home
RUN	echo "${user}:${pass}" | chpasswd && usermod -a -G sudo ${user}

RUN mkdir -p ${SHARED} ${OUT} && \
	chown ${user}:${group} ${SHARED} ${OUT} && \
	chmod 744 ${SHARED} ${OUT}

ARG libpp_path=libpp
ENV LIBPP	${LIBPP_R}/${libpp_path}

ARG program_name
ENV PROGRAM $program_name

# LOAD FUZZER
ARG fuzzer_name
ARG fuzzer_path=fuzzers/${fuzzer_name}
ENV FUZZER      ${LIBPP_R}/${fuzzer_path}
USER root:root
RUN mkdir -p ${FUZZER} && chown ${user}:${group} ${FUZZER}
COPY --chown=${user}:${group} ${libpp_root}/${fuzzer_path} ${FUZZER}/
COPY --chown=${user}:${group} ${libpp_root}/fuzzers/run.sh ${LIBPP_R}/fuzzers/
COPY --chown=${user}:${group} ${libpp_root}/fuzzers/build_and_run.sh ${LIBPP_R}/fuzzers/
RUN ${FUZZER}/preinstall.sh
USER ${user}:${group}
RUN ${FUZZER}/fetch.sh
RUN ${FUZZER}/build.sh

# LOAD TARGET
ARG target_name
ARG target_path=targets/${target_name}
ENV TARGET      ${LIBPP_R}/${target_path}
USER root:root
RUN mkdir -p ${TARGET} && chown ${user}:${group} ${TARGET}
COPY --chown=${user}:${group} ${libpp_root}/${target_path} ${TARGET}/
RUN ${TARGET}/preinstall.sh
USER ${user}:${group}
RUN ${TARGET}/fetch.sh
# RUN ${MAGMA}/apply_patches.sh

ARG BUILD_FLAGS="-g -O"

ENV CFLAGS ${BUILD_FLAGS}
ENV CXXFLAGS ${BUILD_FLAGS}
ENV LIBS -lrt
ENV LDFLAGS -L"${OUT}" -g

# RUN ${FUZZER}/instrument.sh
RUN ${TARGET}/build_library.sh

# ALL THINGS TO SET EXTERNALLY?
ARG timeout_arg=60
ENV TIMEOUT $timeout_arg 
ENV FUZZARGS ""
ENV ARGS "@@"
# ENTRYPOINT "${LIBPP_R}/fuzzers/run.sh"
ENTRYPOINT "${LIBPP_R}/fuzzers/build_and_run.sh"

