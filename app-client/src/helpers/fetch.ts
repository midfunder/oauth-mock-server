import React from 'react';
import axios, { AxiosError } from 'axios';
import { AuthContext } from './AuthProvider';

export interface IFetchState<Type> {
    isLoading: boolean
    isError: boolean
    epoch: number
    data?: Type
    err?: AxiosError
    invalidate: () => void
};

export interface IFetchAction<Type> {
    type: "init" | "success" | "failure" | "invalidate"
    payload?: Type
    error?: AxiosError
};

export const initialFetchState = {
    isLoading: true,
    isError: false,
    epoch: 0,
    invalidate: () => { }
};

interface GenericFetchReducerFn<Type> {
    (state: IFetchState<Type>, action: IFetchAction<Type>): IFetchState<Type>;
};

function fetchStateReducer<Type>(state: IFetchState<Type>, action: IFetchAction<Type>): IFetchState<Type> {
    switch (action.type) {
        case "init":
            return { ...initialFetchState, epoch: state.epoch };
        case "success":
            return { ...state, isLoading: false, data: action.payload };
        case "failure":
            return { ...state, isLoading: false, isError: true, err: action.error }
        case "invalidate":
            return { ...state, epoch: state.epoch + 1 }
    }
    return state;
}

export const useFetchReducer = <Type extends unknown>(
    path: string, condition?: () => boolean): IFetchState<Type> => {
    const reducer: GenericFetchReducerFn<Type> = fetchStateReducer;
    const [state, dispatcher] = React.useReducer(
        reducer, initialFetchState);

    const authContext = React.useContext(AuthContext);
    const shouldSkip = condition && !condition();
    React.useEffect(() => {
        if (shouldSkip) {
            return;
        }

        let isCanceled = false;
        dispatcher({ type: "init" });
        const Authorization = `Bearer ${authContext.token}`;
        axios.get(path, {headers: {Authorization}})
            .then(response => {
                if (isCanceled) return;
                dispatcher({ type: "success", payload: response.data });
            })
            .catch((reason: AxiosError) => {
                if (isCanceled) return;
                dispatcher({ type: "failure", error: reason })
            });
        return () => { isCanceled = true; }
    }, [authContext.token, path, shouldSkip, state.epoch]);

    if (shouldSkip) {
        return initialFetchState;
    }

    const invalidate = () => {
        dispatcher({ type: "invalidate" });
    };
    return { ...state, invalidate };
}