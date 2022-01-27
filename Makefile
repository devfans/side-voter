GC=go build
BUILD_NODE_PAR = -ldflags "-X github.com/polynetwork/poly/common/config.Version=$(VERSION) -X google.golang.org/protobuf/reflect/protoregistry.conflictPolicy=warn" #-race

side-voter: $(SRC_FILES)
	$(GC)  $(BUILD_NODE_PAR) -o side-voter main.go

clean:
	rm -rf side-voter