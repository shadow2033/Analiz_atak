# Правило Phishing_windows_credentials_powershell_scriptblock

Атака "Phishing_windows_credentials_powershell_scriptblock" направлена на фишинг пользовательских аутентификационных данных с использованием скриптов PowerShell, которые создают поддельные приглашения для входа в систему и заставляют пользователей вводить свои учетные данные.

## Сценарии PowerShell:

- **Invoke-LoginPrompt.ps1**: Этот скрипт создает поддельное окно приглашения для входа в систему, которое маскируется под официальное окно для ввода учетных данных.

- **Invoke-CredentialsPhish.ps1**: Этот скрипт также используется для сбора учетных данных пользователей. Вероятно, он использует различные методы для обмана пользователей.

## Методы сбора данных:

- **API CredentialPicker**: Вероятно, скрипты используют API CredentialPicker для отображения поддельного окна входа, чтобы попробовать обмануть пользователей и заставить их ввести свои учетные данные.

- **Resolve-DnsName PowerShell**: Сценарии могут использовать этот инструмент для эксфильтрации данных, возможно, для передачи собранных учетных данных на удаленный сервер через DNS-трафик.

- **ConfigSecurityPolicy Защитника Windows**: Этот элемент может использоваться для выполнения произвольных запросов, возможно, для обхода механизмов безопасности и передачи учетных данных на удаленный сервер.

**Цель атаки:** Целью атаки "Phishing_windows_credentials_powershell_scriptblock" является сбор учетных данных пользователей, представив поддельное приглашение для входа в систему.

## Описание правила

Правило "Phishing_windows_credentials_powershell_scriptblock" предназначено для обнаружения выполнения определенных скриптов PowerShell, связанных с фишингом учетных данных, и попыток извлечения сетевых учетных данных в ходе их выполнения.

### Событие Powershell_ScriptBlock_Execute:

Это событие относится к выполнению скриптов PowerShell.

- **key:** Ключ события основан на исходном хосте, с которого произошло событие.

- **filter:** Условия фильтрации:
  - `filter::NotFromCorrelator()`: Событие не должно быть отправлено коррелятором.
  - `msgid == "4104"`: Идентификатор сообщения события (msgid) должен быть равен "4104".
  - `action == "execute"`: Действие (action) должно быть "execute".
  - `event_src.title == "windows"`: Заголовок события должен быть равен "windows".
  - `object == "command"`: Объект события должен быть "command".

        Далее указываются несколько условий, чтобы определить выполнение определенных команд в командной строке PowerShell:
        - `find_substr(lower(object.process.cmdline), "invoke-loginprompt") != null`: Если командная строка содержит строку "invoke-loginprompt".
        - `find_substr(lower(object.process.cmdline), "invoke-credentialsphish") != null`: Если командная строка содержит строку "invoke-credentialsphish".
        - `find_substr(lower(object.process.cmdline), "$cred.getnetworkcredential()") != null` или `find_substr(lower(object.process.cmdline), "$credential.getnetworkcredential()") != null`: Если командная строка содержит строки связанные с получением учетных данных.
        - `find_substr(lower(object.process.cmdline), "$ds.validatecredentials") != null`: Если командная строка содержит строку "$ds.validatecredentials".
