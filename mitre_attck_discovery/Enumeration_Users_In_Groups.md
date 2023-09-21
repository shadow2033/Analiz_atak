# Правило Enumeration Users in Groups

Атака "Enumeration Users in Groups" представляет собой попытку злоумышленника получить информацию о пользователях, состоящих в группах на целевой системе. Целью этой атаки является сбор информации о структуре системы, что может быть полезным для планирования дальнейших атак.

## Методы атаки:

1. **Net.exe и Net1.exe:** Эти утилиты Windows предоставляют функциональность для работы с сетевыми ресурсами и учетными записями пользователей. Злоумышленники могут использовать команды, такие как net group или net localgroup, чтобы перечислить пользователей в группах.

2. **PowerShell:** Злоумышленники могут использовать PowerShell скрипты для получения информации о группах пользователей и их членах. PowerShell предоставляет богатые возможности для автоматизации таких задач.

**Цель атаки:** Целью атаки "Enumeration Users in Groups" является сбор информации о структуре системы, включая пользователей, их членство в группах и другие атрибуты. Полученная информация может быть использована злоумышленниками для дальнейшего планирования атак, включая атаки на учетные записи, перебор паролей или выполнение привилегированных операций.

## Описание правила

Правило "Enumeration_Users_In_Groups" предназначено для обнаружения событий, связанных с попытками перечисления групп пользователей в операционной системе Windows с использованием инструментов net.exe и net1.exe.

**Key:**
- `event_src.host` - хост (компьютер), на котором произошло событие.
- `object.process.id` - идентификатор (PID) процесса, связанного с событием.

**Filter:**
- `filter::NotFromCorrelator()` - Этот фильтр исключает события, созданные из коррелятора.
- `in_list(["4799", "4798"], msgid)` - Фильтр на `msgid` события. Этот фильтр включает в себя события с `4799` и `4798`, которые связаны с действиями по перечислению групп.
- `in_list(["net.exe", "net1.exe"], lower(subject.process.name))` - Фильтр на имя процесса. Этот фильтр включает в себя события, в которых имя запущенного процесса является `net.exe` или `net1.exe`. Функция `lower()` используется для приведения имени процесса к нижнему регистру, что делает фильтрацию регистронезависимой.