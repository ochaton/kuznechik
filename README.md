# Наивная реализация алгоритма симметричного блочного шифрования ГОСТ Р34.12─2015 (Кузнечик)

Данная реализация неэффективна и выполнена в рамках учебного курса "Введение в криптографию".

## Testing
```sh
make test
```

## Компиляция
Необходимые утилиты:

* make
* gcc или clang

```sh
make all
```

## Запуск
```sh
build/bin/kuznechik -h # prints help
```

```
cat main.c | build/bin/kuznechik -e -k examples/master.bin -o out.bin # encodes file from stdin to file
build/bin/kuznechik -d -i out.bin -k examples/master.bin
```

