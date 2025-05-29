import { useState, useEffect } from 'react'
import { createRegistration, clearRegistrationsForUser, checkRegistration } from './utils';
import './App.css'

const webauthnRpId = 'localhost';
const webauthnServer = "https://localhost/webauthn/webauthn/server.php";

const ListRegistrations = ({ registrations }) => {
  if (!registrations || registrations.length === 0) {
    return <p>No registrations found.</p>;
  }

  return (
    <>
      <div style={{ fontWeight: "bold", marginBottom: 10 }}>
        Registered credentials:
      </div>
      {registrations.map((reg, idx) => {
        return (
          <table style={{border:'1px solid black', margin: "10px 0" }} key={reg.id || Math.random()}>
            <tbody>
              {Object.keys(reg).map((o, i) => (
                <tr key={idx+'regs'+i}>
                  <td>{o}</td>
                  <td style={{ fontFamily: "monospace", whiteSpace:'pre-wrap', wordWrap:'break-word'}}>{reg[o]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        );
      })}
    </>
  );
}

function App() {

  const [registrations, setRegistrations] = useState([]);
  const [refreshRegistrations, setRefreshRegistrations] = useState(false);

  const [fields, setFields] = useState({
    rpId: webauthnRpId,
    token: '64656d6f64656d6f',
    email: 'demo@z.com',
    userDisplayName: 'Demo Demolin'
  });

  function webauthnParameters(email, token, userDisplayName) {
    return (
      '&type_int=1' +
      '&type_hybrid=1' +
      '&fmt_none=1' +
      '&rpId=' + encodeURIComponent(webauthnRpId) +
      '&userId=' + encodeURIComponent(token) +
      '&userName=' + encodeURIComponent(email) +
      '&userDisplayName=' + encodeURIComponent(userDisplayName) +
      '&userVerification=discouraged'
    );
  }

  const fetchRegistrations = async () => {
    try {
      const url = webauthnServer + '?fn=getStoredDataJson';
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const registrations = await response.json();

      return registrations;
    } catch (error) {
      console.error('Error fetching registrations:', error);
    }
  };

  useEffect(() => {
    setRefreshRegistrations(p => !p);
  }, []);

  useEffect(() => {
    // Load initial registrations from the server
    fetchRegistrations()
    .then(data => {
      if (data && Array.isArray(data)) {
        setRegistrations(data);
      } else {
        console.error('Invalid data format received:', data);
      }
    }
    )
    .catch(error => {
      console.error('Error loading registrations:', error);
    }
    );
  }, [refreshRegistrations]);

  const handleChange = (e) => {
  const { name, type, checked, value } = e.target;

    setFields(f => ({
      ...f,
      [name]: ['checkbox','radio'].includes(type) ? checked : value
    }));
  };

  const handleAction = (action) => {
    const params = webauthnParameters(fields.email, fields.token, fields.userDisplayName);

    switch (action) {
      case 'create':
        createRegistration(params)
          .then(() => setRefreshRegistrations(p => !p))
          .catch(error => console.error('Error during registration:', error));
        break;
      case 'check':
        checkRegistration(params)
          .then(() => setRefreshRegistrations(p => !p))
          .catch(error => console.error('Error during login:', error));
        break;
      case 'clear':
        clearRegistrationsForUser(params)
          .then(() => setRefreshRegistrations(p => !p))
          .catch(error => console.error('Error clearing registrations:', error));
        break;
      default:
        console.warn('Unknown action:', action);
    }
  }

  return (
    <>
      <h1 style={{ margin: "40px 10px 2px 0" }}>lbuchs/WebAuthn</h1>
      <div style={{ fontStyle: "italic" }}>
        A simple PHP WebAuthn (FIDO2) server library.
      </div>
      <div className="splitter">
        <div className="form">
          <div>&nbsp;</div>
          <div>&nbsp;</div>
          <div>
            Simple working demo for the{" "}
            <a href="https://github.com/lbuchs/WebAuthn">lbuchs/WebAuthn</a>{" "}
            library.
          </div>
          <div>
            <div>&nbsp;</div>
            <table>
              <thead>
                <tr>
                  <th>Registration</th>
                  <th>Login</th>
                  <th>Clear</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <button type="button" onClick={() => handleAction('create')}>
                      &#10133; new registration
                    </button>
                  </td>
                  <td>
                    <button type="button" onClick={() => handleAction('check')}>
                      &#10068; login
                    </button>
                  </td>
                  <td>
                    <button type="button" onClick={() => handleAction('clear')}>
                      &#9249; clear registrations for user
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
            <div>&nbsp;</div>

            <div>&nbsp;</div>
            <div style={{ fontWeight: "bold" }}>Relying Party</div>
            <p
              style={{ margin: "0 0 5px 0", fontSize: "0.9em", fontStyle: "italic", }}
            >
              A valid domain string that identifies the WebAuthn Relying Party
              <br />
              on whose behalf a given registration or authentication ceremony is
              being performed.
            </p>
            <div>
              <label htmlFor="rpId">RP ID:</label>
              <input
                type="text"
                id="rpId"
                name="rpId"
                value={fields.rpId}
                onChange={handleChange}
              />
            </div>

            <div>&nbsp;</div>
            <div style={{ fontWeight: "bold" }}>User</div>
            <div style={{ marginBottom: 12 }}>
              <label htmlFor="userId">User token (Hex):</label>
              <input
                type="text"
                id="token"
                name="token"
                value={fields.token}
                onChange={handleChange}
                required
                pattern="[0-9a-fA-F]{2,}"
              />
              <i style={{ fontSize: "0.8em" }}>
                You get the user ID back when checking registration (as
                userHandle), if you're using client-side discoverable
                credentials. You can identify with this ID the user who wants to
                login. A user handle is an opaque byte sequence with a maximum
                size of 64 bytes, and is not meant to be displayed to the user.
                The user handle MUST NOT contain personally identifying
                information about the user, such as a username or e-mail
                address.
              </i>
            </div>
            <div style={{ marginBottom: 12 }}>
              <label htmlFor="email">User Email:</label>
              <input
                type="email"
                id="email"
                name="email"
                value={fields.email}
                onChange={handleChange}
                required
                pattern="[0-9a-zA-Z]{2,}"
              />
              <i style={{ fontSize: "0.8em" }}>
                This is user identifier.
              </i>
            </div>
            <div style={{ marginBottom: 6 }}>
              <label htmlFor="userDisplayName">User Display Name:</label>
              <input
                type="text"
                id="userDisplayName"
                name="userDisplayName"
                value={fields.userDisplayName}
                onChange={handleChange}
                required
              />
              <i style={{ fontSize: "0.8em" }}>
                A human-palatable name for the user account, intended only for
                display.
              </i>
            </div>

            <div>&nbsp;</div>

            <div
              style={{
                marginTop: 20,
                fontSize: "0.7em",
                fontStyle: "italic",
              }}
            >
              Copyright &copy; 2023 Lukas Buchs -{" "}
              <a href="https://raw.githubusercontent.com/lbuchs/WebAuthn/master/LICENSE">
                license therms
              </a>
            </div>
          </div>
        </div>
        <div className="serverPreview">
          <p style={{ marginLeft: 10, fontWeight: "bold" }}>
            Here you can see what's saved on the server:
            <button type='button' onClick={() => setRefreshRegistrations(p => !p)} style={{ marginLeft: 10 }}>
              &#8635; reload
            </button>
          </p>
          <ListRegistrations registrations={registrations} />
        </div>
      </div>
    </>
  );
}

export default App;