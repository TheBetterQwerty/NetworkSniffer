CC=gcc
Cflags=-lpcap
flags=-Wextra -Wall

files=$(wildcard ./src/*.c)
output=./build/probe

.PHONY: all build clean

all: build

build: $(files)
	mkdir -p ./build
	$(CC) -g -o $(output) $(files) $(Cflags) $(flags)

clean:
	rm -fr ./build/
