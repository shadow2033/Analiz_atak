# Правило DCShadow_Attack

Атака "DCShadow_Attack" позволяет злоумышленникам создавать фальшивые контроллеры домена для репликации вредоносных объектов в Active Directory (AD).

## Методы атаки:

1. **Создание поддельного DC:** Злоумышленники регистрируют поддельный контроллер домена (DC), который имитирует поведение настоящего контроллера домена.

2. **Имитация работы DC:** Поддельный DC симулирует работу настоящего контроллера домена, используя протоколы, которые обычно используются только настоящими DC. Это позволяет злоумышленникам внедрять свои данные и изменения в AD.

3. **Управление данными:** Зарегистрированный поддельный DC может внедрять и реплицировать изменения в AD-инфраструктуру, включая учетные данные и ключи. Это может быть использовано для установки бэкдоров и установления постоянного доступа.

**Цель атаки:** Целью атаки "DCShadow_Attack" является создание поддельного контроллера домена (DC), который имитирует настоящий контроллер домена, чтобы внедрять и реплицировать вредоносные объекты и изменения в инфраструктуре AD.

## Описание правила

Правило "DCShadow_Attack" создано для обнаружения потенциальных атак, связанных с использованием метода DCShadow (регистрация поддельного контроллера домена) на системе Active Directory.

### Событие event Computer_Account_Changed:

- **key:** Ключ события формируется на основе исходного хоста, на котором происходит событие.

- **filter:** Условия фильтрации:
  - `filter::NotFromCorrelator()`: Исключает события, созданные коррелятором.
  - `event_src.title == "windows"`: События должны иметь заголовок "windows".
  - `msgid == "4742"`: Это условие требует, чтобы идентификатор сообщения события (msgid) был равен "4742". Это идентификатор сообщения, который обычно связан с событиями, связанными с изменениями учетных записей компьютеров.
  - `regex(lower(datafield2), ".(e3514235-4b06-11d1-ab04-00c04fc2dcd2|gc)/.", 0) != null`: Это условие использует регулярное выражение для анализа содержимого datafield2. Регулярное выражение ищет совпадения с шаблонами "e3514235-4b06-11d1-ab04-00c04fc2dcd2" и "gc".
  - `regex(lower(subject.account.name), ".*$$", 0) == null`: Это условие также использует регулярное выражение для анализа имени учетной записи. Он проверяет, что имя учетной записи не заканчивается символом "$".