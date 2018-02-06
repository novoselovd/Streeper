import requests, urllib
import urllib.request


class ChannelInfo:
    def __init__(self, chat_id):
        self.chat_id = chat_id
        self.subscribers = self.getChatMembersCount()
        self.name = self.getChatTitle()
        self.photo = self.getChatPhoto()

    def getChatMembersCount(self):
        r = requests.get(
            'https://api.telegram.org/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/getChatMembersCount?chat_id=%s' % self.chat_id)
        if not r.json()['ok']:
            raise NameError('error((')
        return r.json()['result']

    def getChatTitle(self):
        r = requests.get(
            'https://api.telegram.org/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/getChat?chat_id=%s' % self.chat_id)
        if not r.json()['ok']:
            raise NameError('error((')
        return r.json()['result']['title']

    def getChatPhoto(self):
        r = requests.get(
            'https://api.telegram.org/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/getChat?chat_id=%s' % self.chat_id)
        if not r.json()['ok']:
            raise NameError('error((')
        file_id = r.json()['result']['photo']['small_file_id']
        file_path = requests.get(
            'https://api.telegram.org/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/getFile?file_id=%s' % file_id
        ).json()['result']['file_path']
        urllib.request.urlretrieve(
            'https://api.telegram.org/file/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/%s' % file_path,
            file_path.split('/')[1]
        )
        return file_path.split('/')[1]


# try:
#     ci = ChannelInfo('@samokatus')
#     print(ci.name)
# except NameError as error:
#     print ('Oohps')
