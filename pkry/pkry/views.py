from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from forms import Command
from Client import *


class Statics:
    client = Client()
    counter = 1
    ip = ''
    username = ''
    password = ''
    command = ''


@csrf_exempt
def connect(request):
    response = 'notset'
    output = ''
    if request.method == 'POST':
        form = Command(request.POST)
        print Statics.counter
        if Statics.counter == 1:
            Statics.username = form.data.get('field').split('$ ')[Statics.counter].split('@')[0]
            Statics.ip = form.data.get('field').split('$ ')[Statics.counter].split('@')[1]
        elif Statics.counter == 2:
            try:
                Statics.client = Client()
                Statics.password = form.data.get('field').split('$ ')[Statics.counter]
                Statics.client.connect_to_server(Statics.ip, 2222)
                Statics.client.authorize__server()
                Statics.client.check_user(Statics.username)
                Statics.client.key_authorize('/home/viva/pkry/pkry/priv_key')
                if Statics.client.pass_authorize(Statics.password) == 'poprawne haslo':
                    Statics.client.negotiate_key()
                    response = 'positive'
                else:
                    Statics.counter = 0
                    response = 'negative'
            except Exception as e:
                Statics.counter = 0

        else:
            try:
                Statics.command = form.data.get('field').split('$ ')[Statics.counter]
                if Statics.client.is_client_authorized and Statics.client.is_server_authorized:
                    output = Statics.client.start_exchange(Statics.command).replace('\n', '=')
                response = 'positive'
            except Exception as e:
                Statics.counter = 0
        Statics.counter += 1

    return render(
        request=request,
        template_name='sshClient.html',
        context={
            'form': Command(),
            'response': response,
            'output': output
        }
    )