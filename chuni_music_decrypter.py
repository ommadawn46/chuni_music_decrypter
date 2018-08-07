# coding: UTF-8
from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IHttpListener
from burp import IParameter
from subprocess import Popen, PIPE
import json
import array

# PyCryptoが使えるPythonのパスを指定する
PYTHON_PATH = '/usr/local/var/pyenv/shims/python'
# 暗号用スクリプトのパスを指定する
CRYPTO_PATH = '/Users/kosuke/BurpModules/chuni_music_decrypter/crypto.py'

# 初期鍵の設定
INIT_KEY = 'EnJ0YC3D3C2018!!'
INIT_IV = 'IVisNotSecret123'

# 暗号用スクリプトの呼び出し
def crypto(mode, text, key, iv, isURL):
    cmd = [PYTHON_PATH, CRYPTO_PATH, mode, text, key, iv, isURL]
    p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    print(out)
    sys.stderr.write(err + '\n')
    return out, err

def encode(text, key, iv, isURL):
    return crypto('-e', text, key, iv, isURL)

def decode(text, key, iv, isURL):
    return crypto('-d', text, key, iv, isURL)


class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):
    # implement IBurpExtender
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        callbacks.setExtensionName("Chuni Music Decrypter")
        callbacks.registerHttpListener(self)
        callbacks.registerMessageEditorTabFactory(self)

        self.key = INIT_KEY
        self.iv = INIT_IV

    # implement IHttpListener
    # レスポンスに暗号鍵・IVをヘッダーとして追加する
    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        if not isRequest:
            content = messageInfo.getResponse()
            info = self._helpers.analyzeResponse(content)

            headersArray = self.extractHeaders(content, isRequest)
            bodyStr = self.extractBody(content, isRequest)

            headersArray.append("X-CEDEC-KEY: " + self.key)
            headersArray.append("X-CEDEC-IV: " + self.iv)

            out, err = decode(bodyStr.tostring(), self.key, self.iv, '1')
            if not self.updateKey(out):
                # 鍵が合わない場合は初期鍵も試す
                out, err = decode(bodyStr.tostring(), INIT_KEY, INIT_IV, '1')
                self.updateKey(out)

            newContent = self._helpers.buildHttpMessage(headersArray, bodyStr)
            messageInfo.setResponse(newContent)

    # implement IMessageEditorTabFactory
    def createNewInstance(self, controller, editable):
        return ChuniMusicInputTab(self, controller, editable)

    # 以下、UTIL的なメソッド
    def updateKey(self, out):
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
        if isRequest:
            info = self._helpers.analyzeRequest(content)
        else:
            info = self._helpers.analyzeResponse(content)
            headers = info.getHeaders()
            if len(headers) <= 1 and info.getStatusCode() == 100:
                content = content[info.getBodyOffset():]
                info = self._helpers.analyzeResponse(content)
        return content[info.getBodyOffset():]

    def extractHeaders(self, content, isRequest):
        if isRequest:
            info = self._helpers.analyzeRequest(content)
            headers = info.getHeaders()
            headersArray = list(headers)
        else:
            info = self._helpers.analyzeResponse(content)
            headers = info.getHeaders()
            headersArray = list(headers)
            if len(headersArray) <= 1:
                info = self._helpers.analyzeResponse(content[info.getBodyOffset():])
                headers = info.getHeaders()
                headersArray.append('')
                headersArray.extend(list(headers))
        return headersArray

    def extractKeyIVFromHeaders(self, headersArray):
        key, iv = None, None
        for header in headersArray:
            if 'X-CEDEC-KEY' in header:
                key = header.split(': ')[1]
            if 'X-CEDEC-IV' in header:
                iv = header.split(': ')[1]
        return key, iv


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
                parameter = self._extender._helpers.getRequestParameter(content, "data")
                text = parameter.getValue()
            else:
                text = self._extender.extractBody(content, isRequest).tostring()
                headersArray = self._extender.extractHeaders(content, isRequest)
                key, iv = self._extender.extractKeyIVFromHeaders(headersArray)

            out, err = decode(text, key, iv, '1')
            self._txtInput.setText(out)
            self._txtInput.setEditable(self._editable)

        self._currentMessage = content
        self._currentIsRequest = isRequest

    # DecryptedDataタブで編集したメッセージを再暗号化する
    def getMessage(self):
        if self._txtInput.isTextModified():
            text = self._txtInput.getText().tostring()
            if self._currentIsRequest:
                out, err = encode(text, self._extender.key, self._extender.iv, '1')
                return self._extender._helpers.updateParameter(self._currentMessage, self._extender._helpers.buildParameter("data", out, IParameter.PARAM_BODY))
            else:
                headersArray = self._extender.extractHeaders(self._currentMessage, self._currentIsRequest)
                key, iv = self._extender.extractKeyIVFromHeaders(headersArray)
                out, err = encode(text, key, iv, '0')
                return self._extender._helpers.buildHttpMessage(headersArray, array.array('b', out))
        else:
            return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()
