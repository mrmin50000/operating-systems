## Build
```make```

## Usage
```
./secure_copy [--mode=sequential|--mode=parallel|--mode=auto] file1.txt [file2.txt ...] output_dir key
```

## Modes
- `--mode=sequential` - Process files one by one
- `--mode=parallel` - Process files with thread pool (max 4 workers)
- `--mode=auto` - Auto-select mode based on file count (<5 sequential, >=5 parallel)

## Examples
```bash
# Auto mode (3 files -> sequential)
./secure_copy f1.txt f2.txt f3.txt output 1

# Auto mode (5 files -> parallel)
./secure_copy f1.txt f2.txt f3.txt f4.txt f5.txt output 1

# Explicit sequential mode
./secure_copy --mode=sequential f1.txt f2.txt output 1

# Explicit parallel mode
./secure_copy --mode=parallel f1.txt f2.txt f3.txt output 1
```
