from certifire import app, auth, config, db, database
from certifire.plugins.acme.register import register
from certifire.plugins.acme.authorize import authorize
from certifire.plugins.acme.issue import issue
from certifire.plugins.acme.revoke import revoke
from flask import abort, g, jsonify, request, url_for

from .models import Account, Order, Certificate

import os
import json
from cartola import fs

@app.route('/api/acme', methods=['POST'])
@auth.login_required
def new_acme_account():
    post_data = post_data = request.form
    email = post_data.get('email')
    server = post_data.get('server')
    if not email:
        post_data = request.get_json(force=True)
        email = post_data.get('email')
        server = post_data.get('server')
    user_id = g.user.id
    if email is None:
        abort(400)
    if server is None:
        server = config.LETS_ENCRYPT_PRODUCTION
    ret, account_id = register(server,email, user_id=user_id)
    if ret:
        return (jsonify({'status': 'New account created', 'id': account_id}), 201,
            {'Location': url_for('get_acme_account', id=account_id, _external=True),
                'account_id': account_id})
    else:
        return (jsonify({'status': 'Account already exists', 'id': account_id}), 200,
            {'Location': url_for('get_acme_account', id=account_id, _external=True),
                'account_id': account_id})

@app.route('/api/acme/<int:id>')
@auth.login_required
def get_acme_account(id):
    account = Account.query.get(id)
    if not account:
        abort(400)
    if g.user.id != account.user_id:
        return (jsonify({'status': 'This account does not belong to you!'}), 400)
    return jsonify({'id': account.id,
                        'email': account.email,
                        'key': account.act_key,
                        'uri': account.act_uri,
                        'server': account.server,
                        'status': 'Valid'})

@app.route('/api/acme')
@auth.login_required
def get_all_acme_account():
    data = {}
    accounts = database.get_all(Account,g.user.id,'user_id')
    for act in accounts:
        act_data = {
            'email': act.email,
            'uri': act.act_uri,
            'server': act.server
        }
        data[act.id] = act_data
    return jsonify(data)

@app.route('/api/order', methods=['POST'])
@auth.login_required
def new_order():
    post_data = request.get_json(force=True)
    domains = post_data.get('domains')
    account = post_data.get('account')
    method = post_data.get('method')
    method = method if method else 'dns'

    if domains is None or domains == []:
        return (jsonify({'status': 'Provide atleast one domain'}), 400)

    account = Account.query.get(account)
    account.initialize()

    if g.user.id != account.user_id:
        return (jsonify({'status': 'This account does not belong to you!'}), 400)

    ret, order_id = authorize(account,domains,method,True,g.user.id)
    if ret:
        return (jsonify({'status': 'New order created, Please wait some time before acessing the order', 'id': order_id}), 201,
            {'Location': url_for('get_order', id=order_id, _external=True)})
    else:
        return (jsonify({'status': 'Order already exists', 'id': order_id}), 200,
            {'Location': url_for('get_order', id=order_id, _external=True)})

@app.route('/api/order/<int:id>')
@auth.login_required
def get_order(id):
    order = Order.query.get(id)
    if not order:
        abort(400)
    if g.user.id != order.user_id:
        return (jsonify({'status': 'This order does not belong to you!'}), 400)
    
    order_path = os.path.join(config.paths['orders'], order.hash)
    order_file = os.path.join(order_path, "order.json")

    if not os.path.exists(order_file):
        return (jsonify({'status': 'Order file not found'}), 400)

    order = Order.deserialize(fs.read(order_file))
    ret = json.loads(order.serialize())
    
    ret['domains'] = order.domains.split(',')
    ret['status'] = order.status
    ret['resolved_cert_id'] = order.resolved_cert_id
    
    return jsonify(ret)

@app.route('/api/order/<int:id>/issue')
@auth.login_required
def issue_order(id):
    order = Order.query.get(id)
    if not order:
        abort(400)
    if g.user.id != order.user_id:
        return (jsonify({'status': 'This order does not belong to you!'}), 400)
    
    account = Account.query.get(order.account_id)
    account.initialize()

    ret, cert_id = issue(account,order,config.DEFAULT_CERT_KEY_SIZE,verbose=True)
    
    if ret:
        return (jsonify({'status': 'Certificate is being issued, Please wait some time before acessing the certificate', 'id': cert_id}), 201,
            {'Location': url_for('get_cert', id=cert_id, _external=True)})
    else:
        return (jsonify({'status': 'Certificate already issued', 'id': cert_id}), 200,
            {'Location': url_for('get_cert', id=cert_id, _external=True)})

@app.route('/api/certificate/<int:id>')
@auth.login_required
def get_cert(id):
    certificate = Certificate.query.get(id)
    if not certificate:
        abort(400)
    if g.user.id != certificate.user_id:
        return (jsonify({'status': 'This certificate does not belong to you!'}), 400)
    
    ret = json.loads(certificate.serialize())
    return jsonify(ret)

@app.route('/api/certificate/<int:id>/revoke')
@auth.login_required
def revoke_cert(id):
    certificate = Certificate.query.get(id)
    if not certificate:
        abort(400)
    if g.user.id != certificate.user_id:
        return (jsonify({'status': 'This certificate does not belong to you!'}), 400)
    
    ret = revoke(certificate)
    
    if ret:
        return (jsonify({'status': 'Revoked'}), 201)
    else:
        return (jsonify({'status': 'Already Revoked'}), 201)