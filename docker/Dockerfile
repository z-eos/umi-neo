FROM graygnuorg/pies:2.20-debian as pies

FROM perl:5.40-bookworm as source
COPY . /usr/src/umi
RUN mv /usr/src/umi/docker /usr/src

FROM perl:5.40-bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    TZ='UTC'

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

ARG BUILD_DEPS="libssl-dev git make gcc"
ARG DEBUG_DEPS="vim net-tools procps busybox"
ARG TALLYMAN_URL
ARG TALLYMAN_GPGKEY

RUN apt-get -qq update && \
    apt-get -qq install -y --no-install-recommends \
    ca-certificates \
    libgd-dev \
    ${BUILD_DEPS} \
    ${DEBUG_DEPS}

RUN if test -n "${TALLYMAN_URL}"; then \
      if test -n "${TALLYMAN_GPGKEY}"; then \
        gpg --keyserver keyserver.ubuntu.com --recv-keys ${TALLYMAN_GPGKEY} && \
        mkdir -p /etc/apt/keyrings && \
        gpg --output=/etc/apt/keyrings/${TALLYMAN_GPGKEY}.gpg --export ${TALLYMAN_GPGKEY}; \
        S=" signed-by=/etc/apt/keyrings/${TALLYMAN_GPGKEY}.gpg"; \
      else \
        S=;\
      fi; \
      . /etc/os-release && echo "deb [arch=amd64$S] ${TALLYMAN_URL}/${VERSION_CODENAME} ${VERSION_CODENAME} main" > "/etc/apt/sources.list.d/tallyman.list"; \
      apt-get -qq update && apt-get -qq install -y --no-install-recommends tallyman; \
    fi

RUN cpan -T -i \
    Mojolicious \
    Mojolicious::Plugin::Authentication \
    Mojolicious::Plugin::Authorization \
    Mojolicious::Plugin::StaticCache \
    Mojolicious::Plugin::CHI \
    Crypt::HSXKPasswd \
    Crypt::X509 \
    Crypt::X509::CRL \
    Data::Printer \
    Digest::SHA \
    File::Path \
    File::Temp \
    File::Which \
    GD \
    GD::Barcode::QRcode \
    IPC::Run \
    Net::CIDR::Set \
    Net::DNS \
    Net::LDAP \
    Text::vCard \
    Try::Tiny

WORKDIR /
COPY --from=source /usr/src/umi /umi
COPY --from=pies /pies  /pies
COPY --from=source /usr/src/docker/tree/pies.d /pies/conf.d
COPY --from=source /usr/src/docker/healthcheck /umi
COPY --from=source /usr/src/docker/tallywrap-on /umi
COPY --from=source /usr/src/docker/tallywrap-no /umi

WORKDIR /umi
ENV PATH="/pies/sbin:/pies/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN if command -v tallyman >/dev/null 2>&1; then \
      ln -fs /umi/tallywrap-on /umi/tallywrap; \
    else \
      ln -fs /umi/tallywrap-no /umi/tallywrap; \
    fi

HEALTHCHECK \
    CMD /umi/tallywrap ${UMI_HEALTHCHECK_COLLECTOR:+-s$UMI_HEALTHCHECK_COLLECTOR} -- "${UMI_SRVID:-umi}" /umi/healthcheck

EXPOSE 3000 8073
ENTRYPOINT ["/pies/conf/rc"]

# RUN rm -rf /usr/src/* && \
#     apt-get purge -y --auto-remove ${BUILD_DEPS} && \
#     rm -rf /var/lib/apt/lists/*

# https://opencontainers.org/
# https://github.com/opencontainers/image-spec/blob/master/annotations.md#pre-defined-annotation-keys
LABEL org.opencontainers.image.title="UMI image" \
    org.opencontainers.image.authors="zeus@gnu.org.ua" \
    org.opencontainers.image.documentation="https://github.com/z-eos/umi-neo" \
    org.opencontainers.image.description="\
    sofware.pies.port=8073; \
    sofware.pies.url=http://ps.gnu.org.ua/software/pies/;"
