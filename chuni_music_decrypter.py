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

def encode(text, key, iv, isURL):
    return crypto('-e', text, key, iv, isURL)

def decode(text, key, iv, isURL):
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

        self.request_keys = {}
        self.response_keys = {}

    # implement IHttpListener
    # リクエスト・レスポンスを鍵とした暗号鍵・IVの辞書を作る
    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        if not isRequest:
            response = messageInfo.getResponse()
            request = messageInfo.getRequest()
            responseBody = self.extractBody(response, isRequest)

            self.request_keys[request.tostring()] = (self.key, self.iv)
            self.response_keys[response.tostring()] = (self.key, self.iv)

            out, err = decode(responseBody.tostring(), self.key, self.iv, '1')
            if not self.updateKey(out):
                # 鍵が合わない場合は初期鍵も試す
                out, err = decode(responseBody.tostring(), INIT_KEY, INIT_IV, '1')
                if self.updateKey(out):
                    self.request_keys[request.tostring()] = (INIT_KEY, INIT_IV)
                    self.response_keys[response.tostring()] = (INIT_KEY, INIT_IV)

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
            key, iv = self._extender.key, self._extender.iv
            if isRequest:
                # リクエストボディの復号
                if content.tostring() in self._extender.request_keys:
                    key, iv = self._extender.request_keys[content.tostring()]
                parameter = self._extender._helpers.getRequestParameter(content, "data")
                message = parameter.getValue()
            else:
                # レスポンスボディの復号
                if content.tostring() in self._extender.response_keys:
                    key, iv = self._extender.response_keys[content.tostring()]
                message = self._extender.extractBody(content, isRequest).tostring()
            out, err = decode(message, key, iv, '1')
            self._txtInput.setText(out)
            self._txtInput.setEditable(self._editable)

        self._currentMessage = content
        self._currentIsRequest = isRequest

    # DecryptedDataタブで編集したメッセージを再暗号化する
    def getMessage(self):
        if self._txtInput.isTextModified():
            message = self._txtInput.getText().tostring()
            key, iv = self._extender.key, self._extender.iv
            if self._currentIsRequest:
                # リクエストボディの暗号化
                if self._currentMessage.tostring() in self._extender.request_keys:
                    key, iv = self._extender.request_keys[self._currentMessage.tostring()]
                out, err = encode(message, key, iv, '1')
                content = self._extender._helpers.updateParameter(self._currentMessage, self._extender._helpers.buildParameter("data", out, IParameter.PARAM_BODY))
            else:
                # レスポンスボディの暗号化
                if self._currentMessage.tostring() in self._extender.response_keys:
                    key, iv = self._extender.response_keys[self._currentMessage.tostring()]
                headersArray = self._extender.extractHeaders(self._currentMessage, self._currentIsRequest)
                out, err = encode(message, key, iv, '0')
                content = self._extender._helpers.buildHttpMessage(headersArray, array.array('b', out))

            headersArray = self._extender.extractHeaders(content, self._currentIsRequest)
            body = self._extender.extractBody(content, self._currentIsRequest)

            # ボディを再署名し、X-Signatureを書き換える
            for i in range(len(headersArray)):
                if 'X-Signature' in headersArray[i]:
                    headersArray[i] = 'X-Signature: ' + hmac_sign(message)
                    break
            return self._extender._helpers.buildHttpMessage(headersArray, body)
        else:
            return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()
