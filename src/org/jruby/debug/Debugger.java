/*
 * header & license
 * Copyright (c) 2007-2008 Martin Krauskopf
 * Copyright (c) 2007 Peter Brant
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package org.jruby.debug;

import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.Map;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyString;
import org.jruby.RubyThread;
import org.jruby.debug.DebugBreakpoint.Type;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

final class Debugger {

    private DebugEventHook debugEventHook;
    
    private Map<RubyThread, Context> threadsTable = new IdentityHashMap<RubyThread, Context>();
    
    private IRubyObject breakpoints;
    private IRubyObject catchpoints;
    private boolean tracing;
    private boolean postMortem;
    private boolean keepFrameBinding;
    private boolean debug;
    private boolean trackFrameArgs;

    private IRubyObject lastContext;
    private IRubyObject lastThread;

    private boolean started;
    private int startCount;
    
    /** Used to for unique breakpoint ID for newly added breakpoints. */
    private int lastBreakpointID;

    private DebugContext lastDebugContext;

    IRubyObject start(ThreadContext tc, IRubyObject recv, Block block) {
        startCount++;
        IRubyObject result;
        if (started) {
            result = tc.runtime.getFalse();
        } else {
            IRubyObject nil = tc.runtime.getNil();
            lastThread  = nil;
            started = true;
            setLastContext(nil);
            debugEventHook = new DebugEventHook(this, tc.runtime);
            breakpoints = tc.runtime.newArray();
            catchpoints = RubyHash.newHash(tc.runtime);
            tc.runtime.addEventHook(debugEventHook);
            result = tc.runtime.getTrue();
        }
        
        if (block.isGiven()) {
            try {
                return block.yield(tc, recv);
            } finally {
                stop(tc);
            }
        }
        
        return result;
    }

    boolean stop(ThreadContext tc) {
        checkStarted(tc.runtime);
        
        startCount--;
        if (startCount > 0) return false;

        tc.runtime.tearDown();   
        tc.runtime.removeEventHook(debugEventHook);
        breakpoints = null;
        catchpoints = null;
        debugEventHook = null;
        started = false;
        threadsTable.clear();
        return true;
    }

    /** see {@link RubyDebugger#debug_load} */
    void load(ThreadContext tc, IRubyObject recv, IRubyObject[] args) {
        Arity.checkArgumentCount(tc.runtime, args, 1, 3);
        IRubyObject[] actual = Arity.scanArgs(tc.runtime, args, 1, 2);
        IRubyObject file = args[0];
        IRubyObject stop = actual[1];
        IRubyObject incrementStart = actual[2];

        start(tc, recv, Block.NULL_BLOCK);
        if (!incrementStart.isTrue()) {
            startCount--;
        }
        IRubyObject context = getCurrentContext(tc);
        DebugContext debugContext = (DebugContext) context.dataGetStruct();
        debugContext.clearFrames();
        if (stop.isTrue()) {
            debugContext.setStopNext(1);
        }

        try {
          RubyString fileText = file.convertToString();
          tc.runtime.getLoadService().load(fileText.getByteList().toString(), false);
        } finally {
          stop(tc);
        }
    }
    
    IRubyObject getCurrentContext(ThreadContext tc) {
        return contextForThread(tc.getThread());
    }
    
    DebugContext getCurrentDebugContext(ThreadContext tc) {
        return threadContextLookup(tc.getThread(), true).debugContext;
    }

    DebugContextPair threadContextLookup(final RubyThread thread, final boolean wantDebugContext) {
        checkStarted(thread);

        DebugContextPair ctxs = new DebugContextPair();
        if (lastThread == thread && !lastContext.isNil()) {
            ctxs.context = (Context) lastContext;
            if (wantDebugContext) {
                ctxs.debugContext = lastDebugContext;
            }
            return ctxs;
        }

        synchronized (threadsTable) {
            ctxs.context = threadsTable.get(thread);
            if (ctxs.context == null) {
                ctxs.context = debugContextCreate(thread);
                threadsTable.put(thread, ctxs.context);
            }
        }

        DebugContext lDebugContext = (DebugContext) ctxs.context.dataGetStruct();
        if (wantDebugContext) {
            ctxs.debugContext = lDebugContext;
        }

        lastThread = thread;
        setLastContext(ctxs.context);
        lastDebugContext = lDebugContext;
        return ctxs;
    }

    private Context contextForThread(final RubyThread thread) {
        return threadContextLookup(thread, false).context;
    }

    /** Calls {@link #checkStarted(Ruby)} with reciever's runtime. */
    void checkStarted(final IRubyObject recv) {
        checkStarted(recv.getRuntime());
    }
    
    void checkStarted(final Ruby runtime) {
        if (!started) {
            throw runtime.newRuntimeError("Debugger.start is not called yet.");
        }
    }
    
    ThreadContext ensureStarted(ThreadContext context) {
        checkStarted(context.runtime);
        return context;
    }

    private Context debugContextCreate(RubyThread thread) {
        DebugContext debugContext = new DebugContext(thread);
        // if (thread.getType() == thread.getRuntime().getClass(DebuggerDef.DEBUG_THREAD_NAME)) {
        if (thread.getType().getName().equals("Debugger::" + RubyDebugger.DEBUG_THREAD_NAME)) {
            debugContext.setIgnored(true);
        }
        RubyClass cContext = thread.getRuntime().getModule("Debugger").getClass("Context");
        Context context = (Context) cContext.allocate();
        context.dataWrapStruct(debugContext);
        return context;
    }

    IRubyObject getDebugContexts(IRubyObject self) {
        checkStarted(self);
        RubyArray newList = self.getRuntime().newArray();
        RubyArray list = RubyThread.list(self);

        
        synchronized (threadsTable) {
            for (int i = 0; i < list.size(); i++) {
                newList.add(contextForThread((RubyThread) list.entry(i)));
            }
            for (int i = 0; i < newList.size(); i++) {
                Context context = (Context) newList.entry(i);
                DebugContext debugContext = (DebugContext) context.dataGetStruct();
                threadsTable.put(debugContext.getThread(), context);
            }
        }

        return newList;
    }

    void suspend(IRubyObject recv) {
        checkStarted(recv);
        for (Context context : getNonCurrentContexts(recv)) {
            context.suspend0();
        }
    }
    
    void resume(IRubyObject recv) {
        checkStarted(recv);
        for (Context context : getNonCurrentContexts(recv)) {
            context.resume0();
        }
    }

    private @SuppressWarnings("unchecked") Iterable<Context> getNonCurrentContexts(final IRubyObject recv) {
        RubyArray contexts; 
        Context current;   
        
        synchronized (threadsTable) {
            contexts = (RubyArray) getDebugContexts(recv);
            RubyThread thread = recv.getRuntime().getCurrentContext().getThread();
            current = contextForThread(thread);
        }
        
        int len = contexts.getLength();
        for (int i = 0; i < len; i++) {
            Context context = (Context)contexts.entry(i);
            if (context == current) {
                contexts.remove(i);
            }
        }
        return contexts;
    }

    boolean isStarted() {
        return started;
    }

    void setTracing(boolean tracing) {
        this.tracing = tracing;
    }
    
    boolean isTracing() {
        return tracing;
    }

    void setKeepFrameBinding(boolean keepFrameBinding) {
        this.keepFrameBinding = keepFrameBinding;
    }

    boolean isKeepFrameBinding() {
        return keepFrameBinding;
    }

    boolean isTrackFrameArgs() {
        return trackFrameArgs;
    }

    IRubyObject getBreakpoints() {
        return breakpoints;
    }
    
    IRubyObject addBreakpoint(ThreadContext tc, IRubyObject[] args) {
        checkStarted(tc.runtime);
        IRubyObject result = createBreakpointFromArgs(tc, args, ++lastBreakpointID);
        ((RubyArray) breakpoints).add(result);
        return result;
    }

    IRubyObject removeBreakpoint(IRubyObject recv, IRubyObject breakpointId) {
        checkStarted(recv);
        int id = RubyFixnum.fix2int(breakpointId);
        RubyArray breakpointsA = ((RubyArray) breakpoints);
        for(int i = 0; i < breakpointsA.size(); i++) {
            IRubyObject breakpoint = breakpointsA.entry(i);
            DebugBreakpoint debugBreakpoint = (DebugBreakpoint) breakpoint.dataGetStruct();
            if(debugBreakpoint.getId() == id) {
                breakpointsA.remove(i);
                return breakpoint;
            }
        }
        return Util.nil(recv);
    }
    
    IRubyObject createBreakpointFromArgs(ThreadContext tc, IRubyObject[] args) {
        return createBreakpointFromArgs(tc, args, ++lastBreakpointID);
    }

    IRubyObject createBreakpointFromArgs(ThreadContext tc, IRubyObject[] args, int id) {
        Ruby rt = tc.getRuntime();

        IRubyObject expr;
        if (Arity.checkArgumentCount(rt, args, 2, 3) == 3) {
            expr = args[2];
        } else {
            expr = rt.getNil();
        }
        IRubyObject source = args[0];
        IRubyObject pos = args[1];
        
        Type type = pos instanceof RubyFixnum ? DebugBreakpoint.Type.POS : DebugBreakpoint.Type.METHOD;
        if (type == DebugBreakpoint.Type.POS) {
            source = source.asString();
        } else {
            pos = pos.asString();
        }
        DebugBreakpoint debugBreakpoint = new DebugBreakpoint();
        debugBreakpoint.setId(id);
        debugBreakpoint.setSource(source);
        debugBreakpoint.setType(type);
        if (type == DebugBreakpoint.Type.POS) {
            debugBreakpoint.getPos().setLine(RubyFixnum.num2int(pos));
        } else {
            debugBreakpoint.getPos().setMethodName(((RubyString) pos).toString());
        }
        debugBreakpoint.setExpr(expr.isNil() ? expr : (RubyString) expr);
        debugBreakpoint.setHitCount(0);
        debugBreakpoint.setHitValue(0);
        debugBreakpoint.setHitCondition(DebugBreakpoint.HitCondition.NONE);
        RubyClass cBreakpoint = rt.getModule("Debugger").getClass("Breakpoint");
        IRubyObject breakpoint = cBreakpoint.allocate();
        breakpoint.dataWrapStruct(debugBreakpoint);
        return breakpoint;
    }

    IRubyObject lastInterrupted(IRubyObject recv) {
        checkStarted(recv);
        IRubyObject result = Util.nil(recv);
        synchronized (threadsTable) {
            for (Map.Entry<RubyThread, Context> entry : threadsTable.entrySet()) {
                IRubyObject context = entry.getValue();
                DebugContext debugContext = (DebugContext) context.dataGetStruct();
                if (debugContext.getThnum() == debugEventHook.getLastDebuggedThnum()) {
                    result = context;
                    break;
                }
            }
        }
        return result;
    }
    

    void checkThreadContexts(Ruby runtime) {
        synchronized (threadsTable) {
            for (Iterator<Map.Entry<RubyThread, Context>> it = threadsTable.entrySet().iterator(); it.hasNext();) {
                Map.Entry<RubyThread, Context> entry = it.next();
                if (entry.getKey().alive_p().isFalse()) {
                    it.remove();
                }
            }
        }
    }    
    
    IRubyObject skip(ThreadContext tc, Block block) {
        if (! block.isGiven()) throw tc.runtime.newArgumentError("called without a block");
        
        DebugContext context = getCurrentDebugContext(tc);
        try {
            context.setSkipped(true);
            return block.yield(tc, tc.runtime.getNil());
        } finally {
            context.setSkipped(false);
        }
    }

    boolean isPostMortem() {
        return postMortem;
    }

    void setPostMortem(boolean postMortem) {
        this.postMortem = postMortem;
    }

    boolean isDebug() {
        return debug;
    }

    void setDebug(boolean debug) {
        this.debug = debug;
    }

    /** TODO: Get rid of me - here because of hard rewrite from C. */
    static final class DebugContextPair {
        Context context;
        DebugContext debugContext;
    }

    private void setLastContext(IRubyObject value) {
        lastContext = value;
    }

    void setTrackFrameArgs(boolean trackFrameArgs) {
        this.trackFrameArgs = trackFrameArgs;
    }
    
    RubyHash getCatchpoints() {
        return (RubyHash) catchpoints;
    }
    
    void addCatchpoint(IRubyObject recv, IRubyObject catchpoint) {
        Ruby runtime = recv.getRuntime();
        checkStarted(recv);
        if (catchpoint.isNil()) {
            this.catchpoints = runtime.getNil();
        } else {
            if (!runtime.getString().isInstance(catchpoint)) {
                throw runtime.newTypeError("value of checkpoint must be String");
            }
            getCatchpoints().op_aset(runtime.getCurrentContext(), catchpoint.dup(), RubyFixnum.zero(runtime));
        }
    }
}
