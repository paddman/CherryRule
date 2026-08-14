.PHONY: validate compile test check clean

validate:
	python3 tools/validate_catalog.py

compile:
	python3 tools/compile_bundle.py

test:
	go run tools/re2lint.go

check:
	python3 tools/validate_catalog.py
	python3 tools/compile_bundle.py --check
	go run tools/re2lint.go

clean:
	rm -f dist/cherry-rules.bundle.yaml \
	      dist/cherry-rules.bundle.json \
	      dist/cherry-rules.re2-catalog.json \
	      dist/cherry-rules.visual-studio.json \
	      dist/re2-patterns.json \
	      docs/CATALOG_STATS.md
