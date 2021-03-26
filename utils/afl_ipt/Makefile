all:	afl-ipt

libhoney_analyzer.a:
	test -d Honeybee || git clone --depth=1 https://github.com/trailofbits/Honeybee
	test -e Honeybee/dependencies/libipt/lib/libipt.a || { cd Honeybee/dependencies ; ./build_dependencies.sh ; }
	test -e Honeybee/build/libhoney_analyzer.a || { mkdir -p Honeybee/build && cd Honeybee/build && cmake .. && cmake --build . --target all ; }

afl-ipt2:	afl-ipt2.c honeybee.c libhoney_analyzer.a
	$(CC) -O3 -I../../include -o afl-ipt2 afl-ipt2.c honeybee.c -LHoneybee/build -lhoney_analyzer

afl-ipt:	afl-ipt.c perf.c
	$(CC) -O3 -I../../include -o afl-ipt afl-ipt.c perf.c -lxdc

clean:
	rm -f afl-ipt afl-ipt2 *.o *~ core
