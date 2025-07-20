import React, { useState } from 'react';

function AuthForm() {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (isLogin) {
      console.log('Logging in with:', email, password);
    } else {
      console.log('Registering with:', email, password);
    }
  };

  return (
    <div style={styles.container}>
      <h2>{isLogin ? 'Login' : 'Register'}</h2>
      <form onSubmit={handleSubmit} style={styles.form}>
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          style={styles.input}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          style={styles.input}
        />
        <button type="submit" style={styles.button}>
          {isLogin ? 'Login' : 'Register'}
        </button>
      </form>
      <p>
        {isLogin ? 'New user?' : 'Already have an account?'}{' '}
        <span style={styles.link} onClick={() => setIsLogin(!isLogin)}>
          {isLogin ? 'Register here' : 'Login here'}
        </span>
      </p>
    </div>
  );
}

const styles = {
  container: {
    maxWidth: '400px',
    margin: '80px auto',
    padding: '20px',
    border: '1px solid #ccc',
    borderRadius: '12px',
    backgroundColor: '#f8f8f8',
    textAlign: 'center',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '15px',
  },
  input: {
    padding: '10px',
    fontSize: '16px',
  },
  button: {
    padding: '10px',
    backgroundColor: '#222',
    color: 'white',
    border: 'none',
    cursor: 'pointer',
    borderRadius: '8px',
  },
  link: {
    color: 'blue',
    cursor: 'pointer',
    textDecoration: 'underline',
  },
};

export default AuthForm;
