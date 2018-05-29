# password-manager
Менеджер паролей на Python

Русский
___________________________________________________________________________________________________________________________________________
  Программа поддерживает большое количество пользователей. На данный момент список всех пользователей хранится в текстовом файле. Логины хранятся в открытом виде, а вместо паролей хранятся хеши. При этом хеш берется не от пароля а от конкатенации имени пользователя и пароля. Таким образом даже если пользователи имеют одинаковый пароль, хеши будут отличаться.
   База данных паролей каждого пользователя хранится в отдельном текстовом файле. Эти файлы шифруются при помощи алгоритма AES. В качестве ключа для шифрования принимается хеш от пароля пользователя.
   
   На данный момент разрабатывается консольный интерфейс, в дальнейшем будет разработан также графический.
   
 English
___________________________________________________________________________________________________________________________________________
   Program supports multi-user work. For now the list of users is stored in txt file. Usernames are stored uncovered and instead of passwords stores hashes, which are calculated using concatenation of username and password. So even if two users have similar password their hashes are different.
   The passwords databases for each user is stored in separated files. This files are encrypted with AES. For the key takes the hash of user password.
   
   For now I'm developing console interface but in future I'll make GUI.
