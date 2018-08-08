# coding: UTF-8
from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IHttpListener
from burp import IParameter
from subprocess import Popen, PIPE
import json
import array
import os
import hashlib
import hmac

# PyCryptoが使えるPython2系バイナリのパス
PYTHON_PATH = '/usr/local/var/pyenv/versions/2.7.14/bin/python'
# 暗号用スクリプトのパス
CRYPTO_PATH = './tool/crypto.py'

# 初期鍵の設定
INIT_KEY = 'EnJ0YC3D3C2018!!'
INIT_IV = 'IVisNotSecret123'

# リクエストボディの署名鍵
HMAC_KEY = 'newHmacKey'

def crypto(mode, text, key, iv, isURL):
    '''暗号用スクリプトの呼び出し'''
    cmd = [PYTHON_PATH, CRYPTO_PATH, mode, text, key, iv, isURL]
    p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    return out, err

def encrypt(text, key, iv, isURL):
    return crypto('-e', text, key, iv, isURL)

def decrypt(text, key, iv, isURL):
    return crypto('-d', text, key, iv, isURL)

def hmac_sign(m):
    '''HMACで署名する'''
    return hmac.new(HMAC_KEY, m, hashlib.sha256).hexdigest()

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):
    # implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        callbacks.setExtensionName("Chuni Music Decrypter")
        callbacks.registerHttpListener(self)
        callbacks.registerMessageEditorTabFactory(self)

        self.key = INIT_KEY
        self.iv = INIT_IV

        self.keystore = {}

    # implement IHttpListener
    # リクエスト・レスポンスをキーとした暗号鍵・IVの辞書を作る
    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        if not isRequest:
            response = messageInfo.getResponse()
            request = messageInfo.getRequest()
            responseBody = self.extractBody(response, isRequest)

            # 暗号鍵・IVの登録
            self.storeKey(request, self.key, self.iv)
            self.storeKey(response, self.key, self.iv)

            out, err = decrypt(responseBody.tostring(), self.key, self.iv, '1')
            if not self.updateKey(out):
                # 鍵が合わない場合は初期鍵も試す
                out, err = decrypt(responseBody.tostring(), INIT_KEY, INIT_IV, '1')
                if self.updateKey(out):
                    self.storeKey(request, INIT_KEY, INIT_IV)
                    self.storeKey(response, INIT_KEY, INIT_IV)

    # implement IMessageEditorTabFactory
    def createNewInstance(self, controller, editable):
        return ChuniMusicInputTab(self, controller, editable)

    # 以下、UTIL的なメソッド
    def updateKey(self, out):
        '''暗号鍵・IVを更新する'''
        try:
            resp = json.loads(out)
            if 'metadata' in resp:
                if 'key' in resp['metadata']:
                    self.key = resp['metadata']['key']
                if 'iv' in resp['metadata']:
                    self.iv = resp['metadata']['iv']
        except:
            return False
        return True

    def storeKey(self, content, key, IV):
        '''リクエスト・レスポンスのハッシュ値をキーとして暗号鍵・IVを辞書に登録する'''
        digest = hashlib.md5(content.tostring()).hexdigest()
        self.keystore[digest] = (key, IV)

    def getKey(self, content):
        '''リクエスト・レスポンスに対応する鍵を取得する'''
        digest = hashlib.md5(content.tostring()).hexdigest()
        if digest in self.keystore:
            return self.keystore[digest]

    def keyExists(self, content):
        '''リクエスト・レスポンスに対応する暗号鍵が存在するか'''
        digest = hashlib.md5(content.tostring()).hexdigest()
        return digest in self.keystore

    def extractBody(self, content, isRequest):
        '''array型のrequest/responseからボディを抽出する'''
        if isRequest:
            info = self._helpers.analyzeRequest(content)
        else:
            info = self._helpers.analyzeResponse(content)
            headers = info.getHeaders()
            if info.getStatusCode() == 100:
                content = content[info.getBodyOffset():]
                info = self._helpers.analyzeResponse(content)
        return content[info.getBodyOffset():]

    def extractHeaders(self, content, isRequest):
        '''array型のrequest/responseからヘッダーを抽出する'''
        if isRequest:
            info = self._helpers.analyzeRequest(content)
            headers = info.getHeaders()
            headersArray = list(headers)
        else:
            info = self._helpers.analyzeResponse(content)
            headers = info.getHeaders()
            headersArray = list(headers)
            if info.getStatusCode() == 100:
                info = self._helpers.analyzeResponse(content[info.getBodyOffset():])
                headers = info.getHeaders()
                headersArray.append('')
                headersArray.extend(list(headers))
        return headersArray

# class implementing IMessageEditorTab
class ChuniMusicInputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable

        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)

    # implement IMessageEditorTab
    def getTabCaption(self):
        return "DecryptedData"

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        if isRequest:
            return not self._extender._helpers.getRequestParameter(content, "data") is None
        else:
            return not len(self._extender.extractBody(content, isRequest)) <= 0

    # DecryptedDataタブを開いた際にメッセージを復号して表示する
    def setMessage(self, content, isRequest):
        if content is None:
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            # 暗号鍵の取得
            if self._extender.keyExists(content):
                key, iv = self._extender.getKey(content)
            else:
                key, iv = self._extender.key, self._extender.iv
            # 暗号文の取得
            if isRequest:
                encrypted = self._extender._helpers.getRequestParameter(content, "data").getValue()
            else:
                encrypted = self._extender.extractBody(content, isRequest).tostring()
            # 復号してタブに表示
            plain, err = decrypt(encrypted, key, iv, '1')
            self._txtInput.setText(plain)
            self._txtInput.setEditable(self._editable)

        self._currentMessage = content
        self._currentIsRequest = isRequest

    # DecryptedDataタブで編集したメッセージを再暗号化する
    def getMessage(self):
        content, isRequest = self._currentMessage, self._currentIsRequest
        if self._txtInput.isTextModified():
            # 暗号鍵の取得
            if self._extender.keyExists(content):
                key, iv = self._extender.getKey(content)
            else:
                key, iv = self._extender.key, self._extender.iv
            # 編集済みメッセージの取得
            plain = self._txtInput.getText().tostring()

            if isRequest:
                # 暗号化してリクエストボディに追加
                encrypted, err = encrypt(plain, key, iv, '1')
                data_param = self._extender._helpers.buildParameter("data", encrypted, IParameter.PARAM_BODY)
                content = self._extender._helpers.updateParameter(content, data_param)
            else:
                # 暗号化してレスポンスボディに追加
                encrypted, err = encrypt(plain, key, iv, '0')
                headersArray = self._extender.extractHeaders(content, isRequest)
                content = self._extender._helpers.buildHttpMessage(headersArray, array.array('b', encrypted))

            # ボディを再署名し、X-Signatureを書き換える
            headersArray = self._extender.extractHeaders(content, isRequest)
            for i in range(len(headersArray)):
                if 'X-Signature' in headersArray[i]:
                    headersArray[i] = 'X-Signature: ' + hmac_sign(plain)
                    break
            body = self._extender.extractBody(content, isRequest)
            newContent = self._extender._helpers.buildHttpMessage(headersArray, body)

            # 暗号鍵・IVの登録
            self._extender.storeKey(newContent, key, iv)
            return newContent
        else:
            return content

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()
