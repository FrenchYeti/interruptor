VERSION=0.2.0

clean:
	rm -rf ./dist

compile: clean
	npx tsc

pack: compile
	npx webpack --config webpack.android.arm64.config.js
	npx webpack --config webpack.android.x64.config.js

all: pack
	mkdir ./dist
	cp ./*-strace.min.js ./dist/.
