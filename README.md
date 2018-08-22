# Chuni Music Decrypter
SECCON 2018 x CEDEC CHALLENGE用 BurpSuite拡張モジュール

## Installation
PyCryptoをインストール

`$ pip install pycrypto`

Jython 2.7.0 - Standalone Jar をダウンロード

http://www.jython.org/downloads.html

BurpSuiteにJythonのパスを設定

<img src="https://raw.githubusercontent.com/ommadawn46/chuni_music_decrypter/image/jython_path.png" width="500px">

## Setting
chuni_music_decrypter.py の`PYTHON_PATH`をPyCryptoをインストールしたPythonのパスに書き換える

pyenvを使用していると`python`ではglobalに設定したバイナリを呼んでくれないので直接パスを指定する必要がある

<img src="https://raw.githubusercontent.com/ommadawn46/chuni_music_decrypter/image/python_path.png" width="500px">

BurpSuiteのExtenderにchuni_music_decrypter.pyを追加する

chuni_music_decrypter.pyと同じディレクトリにtool/crypto.pyが無いと動作しないので注意

<img src="https://raw.githubusercontent.com/ommadawn46/chuni_music_decrypter/image/add_extender.png" width="500px">

## Usage
`DecryptedData`タブが追加される

`DecryptedData`タブにはリクエスト・レスポンスのペイロードを復号したものが表示される

内容を書き換えれば実際の通信に反映させることができる

<img src="https://raw.githubusercontent.com/ommadawn46/chuni_music_decrypter/image/decrypted_data_tab.png" width="500px">
