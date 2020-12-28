import json
import os

from certifire import app, auth, config, database, db
from certifire.plugins.acme import crypto
from certifire.plugins.acme.models import Account, Certificate, Order
from certifire.plugins.acme.plugin import (create_order, deregister, register,
                                           reorder, revoke_certificate)
from flask import abort, g, jsonify, request, url_for


@app.route('/api/acme', methods=['POST'])
@auth.login_required
def new_acme_account():
    post_data = post_data = request.form
    email = post_data.get('email')
    server = post_data.get('server')
    organization = post_data.get('organization')
    organizational_unit = post_data.get('organizational_unit')
    country = post_data.get('country')
    state = post_data.get('state')
    location = post_data.get('location')
    key = post_data.get('key')
    if not email:
        post_data = request.get_json(force=True)
        email = post_data.get('email')
        server = post_data.get('server')
        organization = post_data.get('organization')
        organizational_unit = post_data.get('organizational_unit')
        country = post_data.get('country')
        state = post_data.get('state')
        location = post_data.get('location')
        key = post_data.get('key')

    user_id = g.user.id
    if email is None:
        abort(400)
    if server is None:
        server = config.LETS_ENCRYPT_PRODUCTION
    rsa_key = None
    if key:
        rsa_key = crypto.load_private_key(key.encode('UTF-8'))
    
    ret, account_id = register(user_id, email, server, rsa_key,
                               organization, organizational_unit, country, state, location)
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

    ret = json.loads(account.json)
    return jsonify(ret)


@app.route('/api/acme')
@auth.login_required
def get_all_acme_account():
    data = {}
    accounts = database.get_all(Account, g.user.id, 'user_id')
    for act in accounts:
        data[act.id] = json.loads(act.json)
    return jsonify(data)


@app.route('/api/acme/<int:id>', methods=['DELETE'])
@auth.login_required
def deregister_acme(id):
    account = Account.query.get(id)
    if not account:
        abort(400)
    if g.user.id != account.user_id:
        return (jsonify({'status': 'This account does not belong to you!'}), 400)

    ret, _ = deregister(g.user.id, account.id)
    if ret:
        return (jsonify({'status': 'Done'}), 200)
    else:
        return (jsonify({'status': 'Failed'}), 200)


@app.route('/api/order', methods=['POST'])
@auth.login_required
def new_order():
    post_data = request.get_json(force=True)
    domains = post_data.get('domains')
    account = post_data.get('account')
    type = post_data.get('type')
    provider = post_data.get('provider')
    email = post_data.get('email')
    organization = post_data.get('organization')
    organizational_unit = post_data.get('organizational_unit')
    country = post_data.get('country')
    state = post_data.get('state')
    location = post_data.get('location')
    csr = post_data.get('csr')
    key = post_data.get('key')
    reissue = post_data.get('reissue')

    if domains is None or domains == []:
        return (jsonify({'status': 'Provide atleast one domain'}), 400)

    account = Account.query.get(account)

    if g.user.id != account.user_id:
        return (jsonify({'status': 'This account does not belong to you!'}), 400)
    
    pem_key = None
    if key:
        pem_key = crypto.load_private_key(key.encode('UTF-8'))
    
    pem_csr = None
    if csr:
        pem_csr = crypto.load_csr(csr.encode('UTF-8'))

    ret, order_id = create_order(account.id, domains, type, provider, email,
                        organization, organizational_unit, country, state, location, reissue, pem_csr, pem_key)
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

    ret = json.loads(order.json)

    if order.resolved_cert_id:
        return (jsonify(ret), 200, {'Certificate': url_for('get_cert', id=order.resolved_cert_id, _external=True)})
    else:
        return jsonify(ret)

@app.route('/api/order')
@auth.login_required
def get_all_orders():
    data = {}
    orders = database.get_all(Order, g.user.id, 'user_id')
    for order in orders:
        data[order.id] = json.loads(order.json)
    return jsonify(data)

@app.route('/api/certificate/<int:id>')
@auth.login_required
def get_cert(id):
    certificate = Certificate.query.get(id)
    if not certificate:
        return (jsonify({'status': 'There is no such certificate!'}), 400)

    if g.user.id != certificate.user_id:
        return (jsonify({'status': 'This certificate does not belong to you!'}), 400)

    ret = json.loads(certificate.json)
    return jsonify(ret)

@app.route('/api/certificate')
@auth.login_required
def get_all_certificates():
    data = {}
    certs = database.get_all(Certificate, g.user.id, 'user_id')
    for cert in certs:
        data[cert.id] = json.loads(cert.json)
    return jsonify(data)

@app.route('/api/certificate/<int:id>', methods=['DELETE'])
@auth.login_required
def revoke_cert(id):
    certificate = Certificate.query.get(id)
    if not certificate:
        return (jsonify({'status': 'There is no such certificate!'}), 400)

    if g.user.id != certificate.user_id:
        return (jsonify({'status': 'This certificate does not belong to you!'}), 400)

    order = Order.query.get(certificate.order_id)
    if not order:
        return (jsonify({'status': 'Order for this certificate not found'}), 400)
    ret, status = revoke_certificate(order.account_id, certificate.id)

    if ret:
        return (jsonify({'status': status}), 200)
    else:
        return (jsonify({'status': status}), 201)

@app.route('/api/certificate/<int:id>', methods=['PURGE'])
@auth.login_required
def purge_cert(id):
    certificate = Certificate.query.get(id)
    if not certificate:
        return (jsonify({'status': 'There is no such certificate!'}), 400)

    if g.user.id != certificate.user_id:
        return (jsonify({'status': 'This certificate does not belong to you!'}), 400)

    order = Order.query.get(certificate.order_id)
    if not order:
        return (jsonify({'status': 'Order for this certificate not found'}), 400)
    ret, status = revoke_certificate(order.account_id, certificate.id, True)

    if ret:
        return (jsonify({'status': status}), 200)
    else:
        return (jsonify({'status': status}), 201)
