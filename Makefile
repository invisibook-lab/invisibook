.PHONY: build-cli clean

build-cli:
	cd chain && go build -o ../invisibook ./cli/

clean:
	rm -f invisibook
