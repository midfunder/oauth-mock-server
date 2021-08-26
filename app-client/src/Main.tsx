import React from "react";

import { useFetchReducer } from "./helpers/fetch";

interface IValue {
    content: string
};

const MainComponent = () => {
    const valueState = useFetchReducer<IValue>('/api/value');
    if (valueState.isLoading) {
        return <span>Loading...</span>
    }
    if (valueState.isError) {
        return <span>Error {valueState.err?.message} </span>
    }
    return (
        <div className="main">
            <span>{valueState.data?.content}</span>
        </div>
    );
};

export const Main = MainComponent;