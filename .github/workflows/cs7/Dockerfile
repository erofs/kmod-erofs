FROM centos:7 AS builder

COPY . /repo
RUN yum install -y git rpmdevtools sudo
RUN chmod +x /repo/.github/workflows/cs7/rpmbuild.sh

RUN useradd rpmbuild
USER rpmbuild
RUN rpmdev-setuptree
USER root
ARG SPECFILE
WORKDIR /repo
RUN /repo/.github/workflows/cs7/rpmbuild.sh ${SPECFILE}

FROM scratch
COPY --from=builder /home/rpmbuild/rpmbuild/SRPMS /SRPMS
COPY --from=builder /home/rpmbuild/rpmbuild/RPMS /RPMS
