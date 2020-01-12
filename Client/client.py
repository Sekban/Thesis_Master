import requests
import json
from PKE import PKE
import subprocess

API_ENDPOINT = "http://localhost:5000/api/"
server = {
    'server_id': '',
    'server_public_key': '',
    'server_secret': ''
}

def compute_secret(client_pke):                                                                                                                                                                                                                                                                                                
    req_data = {
        'node_id': client_pke.uuid,
        'public_key': client_pke.public_key
    }
    response = requests.post(url = API_ENDPOINT + "authorisation/publickey", data = req_data)
    data = json.loads(response.content)
    server['server_id'] = data['server_id']
    server['server_public_key'] = data['public_key']
    print(server)

    'Then we compute the secret here as well..'
    'Finally we attach the server_secret to every single one of our data requests to do with SEPDP...'

if __name__ == "__main__":
  client_pke = PKE()
  compute_secret(client_pke)