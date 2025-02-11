import React, { Component } from "react";
import Logo from "../style/favicon.png";

export const CspGatewayLogo = ({ size = 40 }) => (
  <img src={Logo} width={`${size}px`} />
);
