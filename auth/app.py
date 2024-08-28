from auth import *


@app.route('/api/auth/login')
def login():
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    return auth0.authorize_redirect(redirect_uri=url_for('callback', _external=True), state=state)

@app.route('/api/auth/callback', methods=['GET', 'POST'])
def callback():
    token = auth0.authorize_access_token()
    if not token:
        return jsonify({'error': 'Failed to retrieve token'}), 401
    # print(token)
    session["user"] = token
    return jsonify({
            "access_token": token['access_token'],
            "id_token": token['id_token'],
            "token_type": token['token_type'],
            "expires_in": token['expires_in'],
            "expires_at": token['expires_at'],
            "scope": token['scope']
        })

@app.route('/api/auth/logout')
def logout():
    session.clear()
    params = {
        'returnTo': url_for('login', _external=True),
        'client_id': app.config['AUTH0_CLIENT_ID']
    }
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params), quote_via=quote_plus)

@app.route('/api/auth/test-session', methods=['GET'])
def test_session():
    if 'user' in session:
        return jsonify(session['user'])
    else:
        return jsonify({'error': 'No user in session'}), 401

@app.route('/api/protected')
@requires_auth
def protected():
    return jsonify({
        'message': 'Hello, World!'
    })
    

    
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8089)