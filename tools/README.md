# tools/

## vsscreate.exe

Вспомогательная утилита для варианта **Windows (VSS)**: создаёт теневой
снимок (shadow copy) тома и экспонирует его на свободную букву диска.

Почему нужна:

- в Windows 11 24H2/25H2 удалена команда `vssadmin create shadow`;
- стандартная точка монтирования снимка (`\\?\GLOBALROOT\...`) не
  читается удалённым rsync'ом (Cygwin/MSYS2) из-за конвертации путей.

Поэтому снимок создаётся через VSS API (чистый COM):

1. `IVssBackupComponents` создаётся из `vssapi.dll`
   (`CreateVssBackupComponents`, экспорт с C++ mangled-именем);
2. контекст — `VSS_CTX_APP_ROLLBACK` (persistent + NO_AUTO_RELEASE,
   writers замораживаются → снимок последовательный);
3. снимок создаётся для нужного тома и экспонируется
   `ExposeSnapshot` на свободную букву диска
   (`VSS_VOLSNAP_ATTR_EXPOSED_LOCALLY`).

Только **persistent** снимок (`VSS_CTX_APP_ROLLBACK`/`VSS_CTX_NAS_ROLLBACK`)
можно экспонировать локально — обычный `VSS_CTX_BACKUP` вернёт
`E_INVALIDARG` (0x80070057).

### Использование

```
vsscreate.exe create <том>:
```

Пример: `vsscreate.exe create C:\`

Вывод (stdout):

```
SHADOW_ID={...}
DEVICE=\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
EXPOSED=Z:\
```

`EXPOSED` — буква диска, на которую экспонирован снимок; rsync читает её
как обычный путь (`Z:\Data` → `/cygdrive/z/Data`).

Снимок нужно удалить после использования:

```
vssadmin delete shadows /shadow={SHADOW_ID}
```

(удаление снимка автоматически освобождает букву диска).

backupd выполняет создание и удаление автоматически; вручную
`vsscreate.exe` нужен только для отладки.

### Сборка

Статический кросс-компилянт MinGW (Windows x86_64, без зависимостей от
DLL):

```
x86_64-w64-mingw32-gcc -O2 -static -Wall -o vsscreate.exe vsscreate.c -lole32
```

Исходник: `vsscreate.c`.
