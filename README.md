# get-rssi
Данная Linux-утилита позволяет получить информацию об изменении уровня WiFi сигнала (RSSI) окружающих точек доступа (Access Point, AP) в течении заданного интервала времени. Утилита выполняет следующее:

1. захват beacon фреймов указанных AP;
2. сохранение захваченных beacons в cap-файл;
3. разбор cap-файла с целью извлечения значений RSSI сигналов WiFi, принимаемых Linux-устройством (на котором запущена утилита) в моменты времени, которые соответствуют приёму каждого beacon фрейма;
4. сохранение значений RSSI в отдельный текстовый файл (txt-файл).

Пользователь задаёт:

+ время, в течение которого будет происходить захват beacon фреймов;
+ MAC-адреса точек доступа, фреймы только которых будут захватываться.

Ограничения (подробнее см. **Примечание**):

+ сетевой интерфейс должен находится в *Monitor* режиме *ПЕРЕД* запуском утилиты;
+ все заданные AP должны работать на *одном и том же* частотном канале;
+ частотный канал сетевого интерфейса должен *совпадать* с частотным каналом заданных AP.

## Установка
Ниже приведён пример установки для Debian Stretch.

1) Установить пакеты, необходимые для сборки и работы утилиты: *build-essential, libpcap0.8, libpcap-dev*. Это можно сделать, например, так:
```
sudo apt-get update
sudo apt-get install build-essential libpcap0.8 libpcap-dev
```

2) Скачать файлы данного репозитория. Можно скачать архивом с помощью браузера (кнопка *Clone or download*); или, если установлен *git*, выполнив команду:
```
git clone https://github.com/h3pr5tq/get-rssi.git
```

3) Для сборки надо перейти в папку проекта *.../get-rssi/* (предварительно разархивировав, если скачивали с помощью браузера) и выполнить команды:
```
make
sudo make install
```
Готово!

Для удаления утилиты выполните `sudo make uninstall` или тоже самое, но напрямую `sudo rm /usr/local/bin/get-rssi`.  
В случае ошибок при сборке необходимо очистить промежуточные файлы. Это можно сделать с помощью команды `make clean`.

## Использование
Пример в случае одной точки доступа:
```
sudo get-rssi  -i mon0  -f ~/rssi  -b 01:FA:23:18:12:F2  -t 100
```
Пример в случае нескольких точек доступа:
```
sudo get-rssi  -i mon0  -f ~/rssi  -b 01:FA:23:18:12:F2,02:bc:19:72:af:ff,01:CC:31:87:af:ff  -t 100
```
Утилита требует 4 обязательных аргумента:

+ `-i` - имя сетевого интерфейса в Monitor режиме;
+ `-f` - префикс для cap- и txt-файла; например, в случае `-f ~/rssi` утилита создаст *~/rssi.cap* и *~/rssi.txt* файлы;
+ `-b` - MAC-адреса точек доступа, beacons только которых будут захватываться; в случае нескольких точек доступа MAC-адреса перечисляем через запятую, *БЕЗ* пробелов;
+ `-t` - время в секундах, в течении которого будет происходить захват beacons; данное значение примерно соответствует времени выполнения утилиты.

По окончанию выполнения утилиты должны получить два файла: cap и txt. Текстовый файл будет иметь следующий вид:  
(В случае одной AP)
```
timestamp (sec):  RSSI (dBm):  BSSID:

0.000000          -79          01:FA:23:18:12:F2
0.102371          -78          01:FA:23:18:12:F2
0.204696          -77          01:FA:23:18:12:F2
0.307270          -78          01:FA:23:18:12:F2
0.409626          -78          01:FA:23:18:12:F2
0.512004          -77          01:FA:23:18:12:F2
0.716764          -78          01:FA:23:18:12:F2
1.024013          -77          01:FA:23:18:12:F2
1.126392          -77          01:FA:23:18:12:F2
1.228766          -81          01:FA:23:18:12:F2
1.331143          -81          01:FA:23:18:12:F2
1.433533          -80          01:FA:23:18:12:F2
1.536041          -84          01:FA:23:18:12:F2
1.638399          -82          01:FA:23:18:12:F2
1.740775          -85          01:FA:23:18:12:F2
2.252738          -84          01:FA:23:18:12:F2
________________________________________________

Number of all sniff beacon frames: 16 (it coincides with number of RSSI values)
BSSID 01:FA:23:18:12:F2 : 16 of 16
```

(В случае двух AP)
```
timestamp (sec):  RSSI (dBm):  BSSID:

0.000000          -85          02:BC:19:72:AF:FF
0.068741          -77          01:FA:23:18:12:F2
0.205759          -84          02:BC:19:72:AF:FF
0.376063          -78          01:FA:23:18:12:F2
0.478443          -76          01:FA:23:18:12:F2
0.512194          -86          02:BC:19:72:AF:FF
0.580815          -76          01:FA:23:18:12:F2
0.683213          -76          01:FA:23:18:12:F2
0.716832          -86          02:BC:19:72:AF:FF
0.819212          -85          02:BC:19:72:AF:FF
0.888077          -76          01:FA:23:18:12:F2
0.921616          -87          02:BC:19:72:AF:FF
0.990374          -77          01:FA:23:18:12:F2
1.023950          -87          02:BC:19:72:AF:FF
1.126447          -88          02:BC:19:72:AF:FF
1.197198          -79          01:FA:23:18:12:F2
1.297653          -77          01:FA:23:18:12:F2
1.400074          -76          01:FA:23:18:12:F2
1.535951          -86          02:BC:19:72:AF:FF
1.604828          -75          01:FA:23:18:12:F2
1.638330          -87          02:BC:19:72:AF:FF
1.707208          -75          01:FA:23:18:12:F2
1.740835          -86          02:BC:19:72:AF:FF
1.809829          -75          01:FA:23:18:12:F2
1.843779          -86          02:BC:19:72:AF:FF
1.912085          -76          01:FA:23:18:12:F2
2.014458          -76          01:FA:23:18:12:F2
________________________________________________

Number of all sniff beacon frames: 27 (it coincides with number of RSSI values)
BSSID 01:FA:23:18:12:F2 : 15 of 27
BSSID 02:BC:19:72:AF:FF : 12 of 27
```

## Примечание
### 1) Настройка сетевого интерфейса для работы с утилитой
Настройка предполгает последовательное выполнение следующих действий:

1. Завершение выполняющихся сетевых процессов, отвечающих за WiFi-соединение (обычно это wpa_supplicant, dhclient, NetworkManager и т.п.). Это необходимо для корректной работы *Monitor* режима.
  + `sudo airmon-ng check kill` - автоматическое завершение сетевых процессов (необходимо установить пакет *aircrack-ng*);
  + `sudo kill PID` или `sudo systemctl stop SERVICE_NAME` - завершение сетевых процессов в ручную, используя стандартные системные утилиты.
2. Включение выбранного сетевого интерфейса (который будем переводить в *Monitor* режим) и отключение лишних (остальных) *беспроводных* сетевых интерфейсов.
  * `sudo iw dev` - просмотр доступных беспроводных сетевых интерфейсов;
  * `sudo ip link set <devname> up` - включение интерфейса;
  * `sudo ip link set <devname> down` - отключение интерфейса.
3. Перевод выбранного сетевого интерфейса в *Monitor* режим.
  * `sudo airmon-ng start <devname>` - используя пакет *aircrack-ng*;  
или
  * `sudo iw dev <devname> set monitor none` - используя стандартную системную утилиту.
4. Конфигурирование выбранного сетевого интерфейса на определённый частотный канал.
  * `sudo iw dev <devname> set channel CHANNEL`, где `CHANNEL` - номер частотного канала: 1 - 13;  
или
  * `sudo iw dev <devname> set freq FREQ` - тоже самое, но указываем центральную частоту FREQ.

### 2) Другое
* Заданные APs (`-b`) должны рабоать на одном и том же частотном канале, который совпадает с частотным каналом сетевого интерфейса Linux-устройства (где запущена утилита). Также необходимо знать MAC-адреса APs. Получить данную информацию удобно с помощью утилиты *airodump-ng* (входит в состав пакета *aircrack-ng*).
* Кол-во захваченных beacons от каждой AP за заданное время зависит от RSSI (для конкретной AP) и beacon interval (параметр AP, показывающий как часто AP будет отправлять beacon фреймы).





