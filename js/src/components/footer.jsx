import React from "react";
import { FaGithub } from "react-icons/fa";

export function Footer(props) {
  // overrideable data
  let { footerLogo } = props;

  return (
    <div className="footer">
      <div className="footer-meta">
        {footerLogo !== undefined && footerLogo}
      </div>
      <div className="footer-meta">
        <a
          href="https://github.com/finos/perspective"
          target="blank"
          className="footer-link"
        >
          <FaGithub size={30} />
        </a>
        <p>
          Built with{" "}
          <a href="https://github.com/finos/perspective" target="blank">
            Perspective
          </a>
        </p>
      </div>
    </div>
  );
}

export default Footer;
