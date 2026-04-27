/* warden — React context for the WardenClient.
 *
 * The client is built once at bootstrap and provided here so child
 * components don't have to thread it through props.  useApi() is the
 * read side.
 */

import React from 'react';

const ApiContext = React.createContext(null);

export function ApiProvider({ client, auth, children }) {
  // Stable ref — auth is created at bootstrap and never reshapes.
  const value = React.useMemo(() => ({ client, auth }), [client, auth]);
  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>;
}

export function useApi() {
  const ctx = React.useContext(ApiContext);
  if (!ctx) throw new Error('useApi() called outside <ApiProvider>');
  return ctx;
}
