# Правило PPL_Bypass_via_PPLDump_Tool

"PPLdump" - это инструмент, написанный на языке программирования C/C++, который служит для обхода механизма PPL и выполнения произвольного кода от имени администратора. Он использует слабости и уязвимости в механизме PPL, чтобы обойти ограничения и проникнуть в процессы, работающие с повышенными привилегиями, такие как процесс "lsass.exe".

## Атака с использованием PPLdump может иметь несколько целей:

1. **Дамп процесса lsass.exe:** Злоумышленник может использовать PPLdump для выполнения дампа процесса "lsass.exe", в котором хранятся учетные данные пользователей.

2. **Перехват библиотек DLL:** PPLdump может также использоваться для внедрения вредоносного кода в системные библиотеки DLL, что позволяет злоумышленнику перехватывать данные и выполнение кода в контексте PPL.

**Цель атаки:** Целью атаки с использованием PPLdump заключается в обходе механизма защиты PPL (Protected Process Light) и выполнении привилегированных действий. Эта атака может быть направлена на дамп процесса "lsass.exe" для извлечения учетных данных пользователей или на перехват системных библиотек DLL для внедрения вредоносного кода и перехвата данных.

## Описание правила

Правило "PPL_Bypass_via_PPLDump_Tool" предназначено для обнаружения атак, связанных с использованием инструмента PPLdump для обхода механизма защиты PPL и для перехвата системных библиотек DLL.

### 1. Событие "PPLdump":

Это правило срабатывает на события, связанные с использованием инструмента PPLdump.

- **key:** Ключ события основан на исходном хосте, с которого произошло событие.
- **filter:** Условия фильтрации:
  - `filter::NotFromCorrelator()`: Убеждается, что событие не является результатом корреляции.
  - `msgid == "1"`: Проверяет, что идентификатор сообщения равен 1.
  - `lower(event_src.title) == "sysmon"`: Убеждается, что источник события имеет заголовок "sysmon".
  - `(in_list(["ppldump.exe", "services.exe", "svchost.exe"], lower(object.process.original_name)) or in_list(["ppldump.exe", "services.exe", "svchost.exe"], lower(object.process.name)))`: Проверяет, что имя процесса (original_name или name) соответствует одному из: "ppldump.exe", "services.exe", "svchost.exe".
  - `(regex(lower(object.process.cmdline), ".ppldump.|.lsass.|.-v.|..dmp.|.localservice.|.fdphost.", 0) != null)`: Проверяет, что командная строка процесса содержит одну из подстрок: "ppldump", "lsass", "-v", ".dmp", "localservice" или "fdphost".

### 2. Событие "PPL_dll":

Это правило срабатывает на события, связанные с перехватом системных библиотек DLL в контексте PPL-процессов.

- **key:** Ключ события основан на исходном хосте, с которого произошло событие.
- **filter:** Условия фильтрации:
  - `filter::NotFromCorrelator()`: Убеждается, что событие не является результатом корреляции.
  - `msgid == "10"`: Проверяет, что идентификатор сообщения равен 10.
  - `lower(event_src.title) == "sysmon"`: Убеждается, что источник события имеет заголовок "sysmon".
  - `(in_list(["ppldump.exe", "csrss.exe", "services.exe", "lsass.exe"], lower(subject.process.name)))`: Проверяет, что имя процесса в качестве источника (subject.process.name) соответствует одному из: "ppldump.exe", "csrss.exe", "services.exe", "lsass.exe".
  - `(in_list(["lsass.exe", "winlogon.exe", "services.exe", "lsass.exe", "dllhost", "svchost.exe"], lower(object.process.name)))`: Проверяет, что имя процесса в качестве объекта (object.process.name) соответствует одному из: "lsass.exe", "winlogon.exe", "services.exe", "lsass.exe", "dllhost", "svchost.exe".
  - `(match(lower(datafield9), ":\windows\system32\ntdll.dll") or match(lower(datafield9), ":\windows\system32\kernelbase.dll") or match(lower(datafield9), ":\windows\system32\kernel32.dll"))`: Проверяет, что в datafield9 присутствует один из путей к системным библиотекам DLL: "ntdll.dll", "kernelbase.dll" или "kernel32.dll".
