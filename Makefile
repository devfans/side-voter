GC=go build

side-voter: $(SRC_FILES)
	$(GC) -o side-voter main.go

clean:
	rm -rf side-voter