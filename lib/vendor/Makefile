build/linux/amd64:
	$(shell docker build -t libinjection-build-linux-amd64 -f Dockerfile.linux_amd64 .)
	$(shell docker run --rm -v $(PWD)/libinjection:/work libinjection-build-linux-amd64 cp libinjection.amd64.so /work/linux_amd64/libinjection.so)

build/linux/aarch64:
	$(shell docker build -t libinjection-build-linux-aarch64 -f Dockerfile.linux_aarch64 .)
	$(shell docker run --rm -v $(PWD)/libinjection:/work libinjection-build-linux-aarch64 cp libinjection.aarch64.so /work/linux_aarch64/libinjection.so)
