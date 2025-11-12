import { Sequelize, DataTypes } from "sequelize";

/**
 * 
 * @returns {Promise<Sequelize>}
 */
export async function loadSequelize() {
    try {
        const sequelize = new Sequelize(/* ... */);
        // ...
        return sequelize;
    } catch (error) {
        console.error(error);
        throw Error("Échec du chargement de Sequelize");
    }

    // ...

}