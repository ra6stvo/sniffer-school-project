# sniffer-school-project

• Приветствую, в этом репозитории находится практическая часть моего проекта. Тут будет представлен готовый код сниффера (является примером и разбирает сетевые пакеты лишь 5 протоколов, но вы можете его дополнять, ведь все основные функции, которые отображают его работу, представлены в коде), процесс написания полностью описан внутри кода комментариями, которые помогут вам разобраться в работе библиотеки libpcap, а также написать собственную подобную программу. Вы также можете запустить мой вариант кода на своем устройстве, а общая инструкция по его запуску и установке основной библиотеки libpcap находится в файле instructions.txt.

• Для кого предназначен проект?

Данный проект написан для пользователей, которые знают язык программирования C на начальном уровне, т.е знают, как работать со встроенными библиотеками данного языка, а также его синтаксис, т.к с нуля написать код такого уровня невозможно. 

• Дополнительные материалы

В файле sniffer.c указаны ресурсы, с которыми вам необходимо ознакомиться, чтобы углубиться в работу этой программы, но я дополнительно продублирую их здесь. Комментариями в коде выделены некоторые функции сторонних библиотек, на указанных ресурсах вы можете изучать работу этих функций отдельно, ведь мы рассматриваем только написание программы - сниффера, которая использует единые необходимые элементы библиотеки libpcap.

Ресурсы для изучения:
  
1. Официальный сайт библиотеки libpcap: https://www.tcpdump.org ; содержание сайта интуитивно понятное, так что проблем с навигацией возникнуть не должно. Чаще всего вам нужно будет находить описание конкретных функций на этом сайте.
2. Библиотека libpcap на github: https://github.com/the-tcpdump-group/libpcap ; здесь вы можете найти коды, которыми написаны готовые функции библиотеки.
