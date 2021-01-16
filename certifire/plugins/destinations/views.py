import json

from certifire import app, auth, database
from certifire.plugins.acme import crypto
from certifire.plugins.destinations.models import Destination
from flask import abort, g, jsonify, request, url_for


@app.route('/api/destination', methods=['POST'])
@auth.login_required
def new_destination():
    post_data = post_data = request.form
    host = post_data.get('host')
    port = post_data.get('port', 22)
    user = post_data.get('user', 'root')
    password = post_data.get('password')
    ssh_priv_key = post_data.get('ssh_priv_key')
    ssh_priv_key_pass = post_data.get('ssh_priv_key_pass')
    challengeDestinationPath = post_data.get('challengeDestinationPath')
    certDestinationPath = post_data.get('certDestinationPath')
    exportFormat = post_data.get('exportFormat')
    if not host:
        post_data = request.get_json(force=True)
        host = post_data.get('host')
        port = post_data.get('port', 22)
        user = post_data.get('user', 'root')
        password = post_data.get('password')
        ssh_priv_key = post_data.get('ssh_priv_key')
        ssh_priv_key_pass = post_data.get('ssh_priv_key_pass')
        challengeDestinationPath = post_data.get('challengeDestinationPath')
        certDestinationPath = post_data.get('certDestinationPath')
        exportFormat = post_data.get('exportFormat')

    user_id = g.user.id
    if host is None:
        return (jsonify({'status': 'host field missing'}), 400)
    if password is None and ssh_priv_key is None:
        return (jsonify({'status': 'password and ssh_priv_key fields missing. Provide atleast one'}), 400)
    key = None
    if ssh_priv_key:
        key = crypto.load_private_key(ssh_priv_key.encode('UTF-8'))

    dest = Destination(user_id=user_id,
                       host=host,
                       port=port,
                       user=user,
                       password=password,
                       ssh_priv_key=key,
                       ssh_priv_key_pass=ssh_priv_key_pass,
                       challengeDestinationPath=challengeDestinationPath,
                       certDestinationPath=certDestinationPath,
                       exportFormat=exportFormat)
    if dest.create():
        return (jsonify({'status': 'New destination created', 'id': dest.id}), 201,
                {'Location': url_for('get_destination', id=dest.id, _external=True),
                 'destination_id': dest.id})
    else:
        status = json.loads(dest.json)
        status['status'] = "Error creating destination with given data. Check hostname, password, private key"
        return (jsonify(status), 400)


@app.route('/api/destination/<int:id>')
@auth.login_required
def get_destination(id):
    dest = Destination.query.get(id)
    if not dest:
        return (jsonify({'status': 'There is no such destination!'}), 404)
    if g.user.id != dest.user_id:
        return (jsonify({'status': 'This destination does not belong to you!'}), 401)

    ret = json.loads(dest.json)
    try:
        dest.open_sftp_connection()
        ret['status'] = 'SSH Connection OK'
        return jsonify(ret)
    except:
        ret['status'] = 'SSH Connection Failed'
        return jsonify(ret), 205


@app.route('/api/destination')
@auth.login_required
def get_all_destinations():
    data = {}
    dests = database.get_all(Destination, g.user.id, 'user_id')
    for dest in dests:
        data[dest.id] = json.loads(dest.json)
    return jsonify(data)


@app.route('/api/destination/<int:id>', methods=['PATCH'])
@auth.login_required
def update_destination(id):
    dest = Destination.query.get(id)
    if not dest:
        return (jsonify({'status': 'There is no such destination!'}), 404)
    if g.user.id != dest.user_id:
        return (jsonify({'status': 'This destination does not belong to you!'}), 401)

    post_data = post_data = request.form
    host = post_data.get('host')
    port = post_data.get('port', 22)
    user = post_data.get('user', 'root')
    password = post_data.get('password')
    ssh_priv_key = post_data.get('ssh_priv_key')
    ssh_priv_key_pass = post_data.get('ssh_priv_key_pass')
    challengeDestinationPath = post_data.get('challengeDestinationPath')
    certDestinationPath = post_data.get('certDestinationPath')
    exportFormat = post_data.get('exportFormat')
    if not (host or port or user or password or
            ssh_priv_key or ssh_priv_key_pass or
            challengeDestinationPath or certDestinationPath or exportFormat):
        post_data = request.get_json(force=True)
        host = post_data.get('host')
        port = post_data.get('port', 22)
        user = post_data.get('user', 'root')
        password = post_data.get('password')
        ssh_priv_key = post_data.get('ssh_priv_key')
        ssh_priv_key_pass = post_data.get('ssh_priv_key_pass')
        challengeDestinationPath = post_data.get('challengeDestinationPath')
        certDestinationPath = post_data.get('certDestinationPath')
        exportFormat = post_data.get('exportFormat')

    user_id = g.user.id
    key = None
    if ssh_priv_key:
        key = crypto.load_private_key(ssh_priv_key.encode('UTF-8'))

    ret = dest.update(user_id=user_id,
                      host=host,
                      port=port,
                      user=user,
                      password=password,
                      ssh_priv_key=key,
                      ssh_priv_key_pass=ssh_priv_key_pass,
                      challengeDestinationPath=challengeDestinationPath,
                      certDestinationPath=certDestinationPath,
                      exportFormat=exportFormat)
    if ret:
        return (jsonify({'status': 'Destination updated', 'id': dest.id}), 202,
                {'Location': url_for('get_destination', id=dest.id, _external=True),
                 'destination_id': dest.id})
    else:
        status = json.loads(dest.json)
        status['status'] = "Error updating destination with given data. Check hostname, password, private key"
        return (jsonify(status), 400)


@app.route('/api/destination/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_destination(id):
    dest = Destination.query.get(id)
    if not dest:
        return (jsonify({'status': 'There is no such destination!'}), 404)
    if g.user.id != dest.user_id:
        return (jsonify({'status': 'This destination does not belong to you!'}), 401)

    try:
        dest.delete()
        return (jsonify({'status': 'Destination deleted'}), 200)
    except:
        return (jsonify({'status': 'Failed  to delete'}), 400)
