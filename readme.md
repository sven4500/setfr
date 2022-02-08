# setfr (send Ethernet frame)

Утилита setfr предназначена для данных по каналу Ethernet. На данный момент реализована возможность отправлять пакеты на уровнях 2 и 3 модели OSI. Посредством командной строки программе передаётся путь к расположению бинарного файла содержащего заранее подготовленный кадр. Бинарный файл кадра помимо полезной нагрузки хранит также заголовки требуемых протоколов.

Например, если выбран режим работы на уровне линков (уровень 2 модели OSI), то файл кадра должен также содержать заголовок Ethernet, заголовок сетевого уровня, например IP, заголовок транспортного уровня, например, UDP, а также данные.

## Параметры командной строки

В приведённой ниже таблице отмечены всё возможные на данный момент параметры командной строки.

| Ключ | Значение | Описание                                                     |
| ---- | -------- | ------------------------------------------------------------ |
| -f   | Путь     | Путь к расположению бинарного файла содержащего кадр для отправки по каналу Ethernet |
| -o   | 2..4     | Уровень на котором осуществляется отправка в соответствии с моделью OSI. (2) уровень линков, (3) сетевой уровень, (4) транспортный уровень. На данный момент реализована возможность отправки только на уровнях 2 и 3. |
| -i   | IPv4     | IPv4 адрес машины получателя. Используется только в режиме работы на уровне 3. Кадр отправляется по указанному адресу игнорируя имеющуюся в кадре информацию. |
| -p   | ..65535  | Номер порта машины получается. Используется только для работы на уровне 3. Кадр отправляется по указанному адресу игнорируя имеющуюся в кадре информацию. |
| -d   | 1..      | Индекс сетевого адаптера. Используется только для работы на уровне 2. |
| -m   | MAC      | MAC адрес машины получателя. Используется только для работы на уровне 2. Формат без разделительных символов, 12 шестнадцатеричных знака. |
| -h   |          | Вывести на экран список возможных команд.                    |

Пример вызова программы для отправки кадра содержащего UDP пакет на 3 уровне:

```shell
setfr -f ./udp-osi-lv-3.bin -o 3 -i 127.0.0.1 -p 8001
```

Во время вызова программе передаётся путь к бинарному файлу содержащему кадр для отправки, уровень модели OSI для которого был построен кадр, адрес машины получателя. Как уже было сказано выше не смотря на то что в кадре уже хранится заголовки IP и UDP содержащие информацию об адресе машины получается, кадр будет отправлен на адрес переданный в командной строке.

```
setfr -f ./udp-osi-lv-2.bin -o 2 -d 2 -m 080027dc5db1
```

Отправка Ethernet кадра на указанный MAC адрес.

## Структура проекта

Проект разбит на несколько каталогов:

- build хранятся проектные файлы (в дальнейшем возможно использование системы автоматизированный сборки, на данный момент не реализовано). На данный момент в каталоге хранятся проекты двух сред: Visual Studio 2015 Express и Qt Creator. Программа не использует Qt и проектный файл настроен на компиляцию без библиотек Qt (не было возможности установить что-либо другое, а отлаживаться в среде немного приятнее чем без неё);
- frames хранятся примеры сетевых кадров. В каталоге находится readme с описанием содержимого кадров;
- src исходный код программы.

## Примечания

Работоспособность программы была проверена на UPD сокетах в ОС Ubuntu 5.11 и Windows 10. На ОС Windows 10 возможно использовать [Геркулес]([Hercules SETUP utility | HW-group.com](https://www.hw-group.com/software/hercules-setup-utility)) отправляя кадры на localhost.

- Для запуска на Unix подобных, вероятно понадобятся права администратора.
- Для запуска на Windows требуются права администратора.
- На Windows запрещено всё что ниже 3 уровня.

