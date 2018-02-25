import requests
import urllib.request


class ChannelInfo:
    def __init__(self, chat_id):
        if 'https://t.me/' in chat_id:
            chat_id = '@%s' % chat_id.split('/')[-1]
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
        if not (r.json()['ok'] and r.json()['result']['type'] == 'channel'):
            raise NameError('error((')
        return r.json()['result']['title']

    def getChatPhoto(self):
        r = requests.get(
            'https://api.telegram.org/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/getChat?chat_id=%s' % self.chat_id)
        if not r.json()['ok']:
            raise NameError('error((')
        if 'photo' not in r.json()['result']:
            return
        file_id = r.json()['result']['photo']['small_file_id']
        file_path = requests.get(
            'https://api.telegram.org/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/getFile?file_id=%s' % file_id
        ).json()['result']['file_path']
        urllib.request.urlretrieve(
            'https://api.telegram.org/file/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/%s' % file_path,
            'images/' + file_path.split('/')[1]
        )
        return file_path.split('/')[1]

# s = 'https://t.me/MachineLearning'
# try:
#     ci = ChannelInfo(s)
#     print(ci.photo)
# except NameError as error:
#     print ('Oohps')
