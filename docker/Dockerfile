FROM graygnuorg/pies:2.20-debian as pies

FROM perl:5.40-bookworm as source
COPY . /usr/src/umi
RUN mv /usr/src/umi/docker /usr/src

FROM perl:5.40-bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    TZ='UTC'

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

RUN apt-get -qq update && \
    apt-get -qq install -y --no-install-recommends \
    ca-certificates \
    libgd-dev

RUN cpan -T -i \
    Mojolicious \
    Mojolicious::Plugin::Authentication \
    Mojolicious::Plugin::Authorization \
    Mojolicious::Plugin::StaticCache \
    Net::LDAP \
    Try::Tiny \
    Data::Printer \
    Crypt::HSXKPasswd \
    File::Which \
    GD \
    GD::Barcode::QRcode \
    IPC::Run

WORKDIR /
COPY --from=source /usr/src/umi /umi
COPY --from=pies /pies  /pies
COPY --from=source /usr/src/docker/tree/pies.d /pies/conf.d

WORKDIR /umi
ENV PATH="/pies/sbin:/pies/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EXPOSE 3000 8073
ENTRYPOINT ["/pies/conf/rc"]
