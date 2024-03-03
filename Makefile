MAKEFLAGS += --no-builtin-rules

.PHONY: all clean _clean _nop

%.min.js: %.js
	sed -E 's/\b(let|const)\b/var/g' $< | \
	terser \
		--ecma 6 -f ascii_only=true -m -o $@ \
		-c passes=3,unsafe=true,booleans_as_integers=true,drop_console=true
	@printf '\n' >> $@

cli.js: atob.js tasmota_fingerprint.js readfile.js
	cat $^ > $@

cli.min.js: atob.js tasmota_fingerprint.min.js readfile.js
	cat $^ > $@

# hack to force clean to run first *to completion* even for parallel builds
# note that $(info ...) prints everything on one line
clean: _nop $(foreach _,$(filter clean,$(MAKECMDGOALS)),$(info $(shell $(MAKE) _clean)))
_clean:
	rm -f cli.js *.min.js || /bin/true
_nop:
	@true
