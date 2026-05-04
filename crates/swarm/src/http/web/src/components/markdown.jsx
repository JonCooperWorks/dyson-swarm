import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkBreaks from 'remark-breaks';

const MD_PLUGINS = [remarkGfm, remarkBreaks];

export function MarkdownBody({ markdown, className = 'md-body' }) {
  return (
    <div className={className}>
      <ReactMarkdown
        remarkPlugins={MD_PLUGINS}
        components={{
          a: MarkdownLink,
        }}
      >
        {markdown || ''}
      </ReactMarkdown>
    </div>
  );
}

function MarkdownLink({ node, href, children, ...props }) {
  const safeHref = safeMarkdownHref(href);
  if (!safeHref) return <>{children}</>;
  const external = /^(https?:|mailto:)/i.test(safeHref);
  return (
    <a
      {...props}
      href={safeHref}
      target={external ? '_blank' : undefined}
      rel={external ? 'noopener noreferrer' : undefined}
    >
      {children}
    </a>
  );
}

export function safeMarkdownHref(href) {
  const value = String(href || '').trim();
  if (!value) return '';
  if (/^(https?:|mailto:)/i.test(value)) return value;
  if (/^(#|\/(?!\/)|\.\/|\.\.\/)/.test(value)) return value;
  return '';
}
