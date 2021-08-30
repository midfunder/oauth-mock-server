import * as React from 'react';
import { useAuth0 } from '@auth0/auth0-react';

export interface IAuthContext {
    isAuthenticated: boolean
    token?: string
    username?: string
    userId?: string
};

export const AuthContext = React.createContext<IAuthContext>({
    isAuthenticated: false,
});
interface IAuthProviderProps {
    children: React.ReactNode;
};

export const AuthProvider = (props: IAuthProviderProps) => {
    const [token, setToken] = React.useState<string>("");
    const { children } = props;

    const { isLoading, isAuthenticated, user, getAccessTokenSilently } = useAuth0();
    const authAvailable = !isLoading && isAuthenticated;
    React.useEffect(() => {
        if (!authAvailable) {
            return;
        }
        getAccessTokenSilently({
            audience: process.env.REACT_APP_AUTH_AUDIENCE,
        })
            .then((tok) => setToken(tok))
            .catch((reason: Error) => { console.log(reason); } );
    }, [authAvailable, getAccessTokenSilently]);

    if (!authAvailable || !token) {
        return <span>Please authenticate...</span>
    }

    const context: IAuthContext = {
        isAuthenticated: true,
        token: token,
        userId: user?.sub,
        username: user?.name,
    }

    return (
        <AuthContext.Provider value={context}>
            {children}
        </AuthContext.Provider>
    )
}
