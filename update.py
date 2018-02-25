import requests
import models


def run():
    channels = models.Channel.query.all()
    for row in channels:
        try:
            r = requests.get(
                'https://api.telegram.org/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/getChatMembersCount?chat_id=%s' % row.link)
            if not r.json()['ok']:
                models.db.session.delete(row)
            else:
                up_todate_name = requests.get(
                    'https://api.telegram.org/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/getChat?chat_id=%s' % row.link).json()['result']['title']
                row.name = up_todate_name

                up_todate_subscribers = requests.get(
                    'https://api.telegram.org/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/getChatMembersCount?chat_id=%s' % row.link).json()['result']
                row.subscribers = up_todate_subscribers
        except:
            pass

        models.db.session.commit()
    print("Database has been updated!")

