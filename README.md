# Chuni Music Decrypter
SECCON 2018 x CEDEC CHALLENGE用 BurpSuite拡張モジュール

## Installation
PyCryptoをインストール

`$ pip install pycrypto`

Jython 2.7.0 - Standalone Jar をダウンロード

http://www.jython.org/downloads.html

BurpSuiteにJythonのパスを設定

<img src="https://raw.githubusercontent.com/ommadawn46/chuni_music_decrypter/image/jython_path.png?token=AJwdE3GA7RxoBeVs_TOmqgyvERVBx_YVks5bdAAnwA%3D%3D" width="500px">

## Setting
chuni_music_decrypter.py の`PYTHON_PATH`をPyCryptoをインストールしたバイナリのパスに書き換える

pyenvを使用していると`python`ではglobalに設定したバイナリを呼んでくれないので直接パスを指定する必要がある

<img src="https://raw.githubusercontent.com/ommadawn46/chuni_music_decrypter/image/python_path.png?token=AJwdEyZKuWWGNvFB7XXFdch7uenKOf4Pks5bdALwwA%3D%3D" width="500px">

BurpSuiteのExtenderにchuni_music_decrypter.pyを追加する

chuni_music_decrypter.pyと同じディレクトリにtool/crypto.pyが無いと動作しないので注意

<img src="https://raw.githubusercontent.com/ommadawn46/chuni_music_decrypter/image/add_extender.png?token=AJwdE0jWJXMw8baMHAKXqZ1SjjYpZ5p6ks5bdAFAwA%3D%3D" width="500px">

## Usage
`DecryptedData`タブが追加される

`DecryptedData`タブにはリクエスト・レスポンスのペイロードを復号したものが表示される

内容を書き換えれば実際の通信に反映させることができる

<img src="https://raw.githubusercontent.com/ommadawn46/chuni_music_decrypter/image/decrypted_data_tab.png?token=AJwdE8Zg9U6Xa6it_hzy8kSRjvW2Bo_pks5bdASQwA%3D%3D" width="500px">
