# Правило Detect_lolbin_pcalua_exec

Атака с использованием Pcalua.exe представляет собой метод, который злоумышленники могут использовать для выполнения произвольных команд на системе, обходя ограничения безопасности, связанные с запуском интерпретаторов командной строки.

## Методы атаки

Злоумышленники могут использовать Pcalua.exe в сочетании с другими инструментами и методами для выполнения своих целей. Это может включать в себя запуск вредоносных скриптов, двоичных файлов или команд, которые могут использоваться для различных целей, включая установку дополнительного вредоносного программного обеспечения.

**Цель атаки:** Главной целью этой атаки может быть выполнение вредоносных команд или программ на целевой системе.

## Описание правила

Правило "Detect_lolbin_pcalua_exec" предназначено для мониторинга запуска процессов, связанных с исполнением Pcalua.exe, и может служить для обнаружения подозрительной активности, связанной с использованием Pcalua.exe для выполнения команд.

### Событие Process_Start_One

- **key:** Ключ события формируется на основе исходного хоста, на котором происходит событие.

- **filter:** Условия фильтрации:
  - `filter::NotFromCorrelator()`: Исключает события, созданные коррелятором.
  - `msgid == "1"`: Событие имеет идентификатор сообщения равный "1".
  - `lower(event_src.title) == "sysmon"`: Заголовок события равен "sysmon".
  - `lower(object) == "process"`: Объект события - процесс.
  - `lower(action) == "start"`: Действие - запуск процесса.
  - `lower(object.process.name) == "pcalua.exe"`: Имя запущенного процесса должно быть "pcalua.exe".
  - `match(lower(object.process.cmdline), "pcalua.exe? -a")`: Командная строка запущенного процесса должна соответствовать заданному шаблону. Здесь используется "*" как символ подстановки.

### Событие Process_Start_Second

- **key:** Ключ события формируется на основе исходного хоста, на котором происходит событие.

- **filter:** Условия фильтрации:
  - `filter::NotFromCorrelator()`: Исключает события, созданные коррелятором.
  - `msgid == "1"`: Событие имеет идентификатор сообщения равный "1".
  - `lower(event_src.title) == "sysmon"`: Заголовок события равен "sysmon".
  - `lower(object) == "process"`: Объект события - процесс.
  - `lower(action) == "start"`: Действие - запуск процесса.
  - `lower(object.process.parent.name) == "pcalua.exe"`: Имя родительского процесса должно быть "pcalua.exe".
  - `match(lower(object.process.parent.cmdline), "pcalua.exe? -a")`: Командная строка родительского процесса должна соответствовать заданному шаблону. Здесь используется "*" как символ подстановки.